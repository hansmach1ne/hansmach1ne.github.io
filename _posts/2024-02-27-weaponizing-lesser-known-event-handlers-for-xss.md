---
title: "Weaponizing lesser known event handlers for XSS"
categories: [Novel Techniques]
tags: XSS Research
---

In the ever-evolving landscape of cybersecurity, one threat remains a persistent adversary - Cross-Site Scripting (XSS). Despite many efforts to mitigate XSS vulnerabilities, hackers continually find new ways to exploit them. In this blog post, we delve into the realm of XSS exploitation through event handlers, exploring cutting-edge techniques that challenge traditional defenses. XSS occurs when attackers inject malicious scripts into web applications, which are then executed in the context of unsuspecting users' browsers. This allows attackers to steal sensitive information, hijack user sessions, deface websites, and much more.

### Rise of Event Handler Exploitation

Event handlers in HTML allow developers to specify JavaScript code that should be executed in response to user actions, such as mouse clicks or keystrokes. While these handlers are essential for building dynamic web applications, they also provide optimal ground for XSS exploitation. By injecting malicious code into event handler attributes, attackers can execute their payloads in contexts that are often overlooked by security filters and protections.

This blog hopefully motivates the rest of the community to deep dive into other interesting handlers (there are many more) and produce novel payloads which can also potentially bypass modern defenses.

### Portswigger's XSS cheat sheet

It's worth noting that new event handler payloads covered in this blogpost have been recently added to PortSwigger's widely acclaimed [XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet). It is a comprehensive resource collaboratively crafted by the cybersecurity research community. This cheat sheet is widely utilized by pentesters, further emphasizing the relevance and practical application of these event handlers in security testing and assessment scenarios.

### The onformdata event handler

The `onformdata` event is triggered when a form is submitted, allowing JavaScript code to intercept and manipulate the form data before it is sent to a server. This event handler opens up a new avenue for attackers to inject malicious scripts and exfiltrate sensitive information entered by users. Once the form has been submitted by an unsuspecting user, the attacker's payload will execute.

An example of a maliciously constructed payload would look like the following, where the example 'malicious' injected code will render the alert window to the user.

```html
<form onformdata=alert()><button>ClickMe</*>
```

### onsuspend

This event is triggered when media playback is suspended, providing a unique mechanism for user engagement. However, in the wrong hands, it can also serve as a vector for exploitation.

The `onsuspend` event occurs when media playback is intentionally or unintentionally paused or delayed. It is commonly associated with audio and video elements, providing developers with a hook to execute JavaScript code when playback is interrupted. While not as commonly utilized as other events, its potential for misuse should not be underestimated. Since browsers automatically suspend the video/audio, the event will trigger instantly once it has been loaded.

```html
<audio controls onsuspend=alert()><source src=validvideo.mp4 type=audio/mpeg></*>
```

### onloadstart

`onloadstart` event fires when the browser starts to load a media resource, such as a video or audio file. It provides developers with an opportunity to execute JavaScript code at the start of media loading. While typically used for legitimate purposes, it can be exploited by attackers to trigger unwanted actions.

```html
<video onloadstart=alert()><source></*>
```

### onwaiting

`onwaiting` event is triggered when playback is paused due to buffering, typically occurring when the media resource isn't fully loaded. It provides developers with an opportunity to execute JavaScript code when playback is temporarily halted, often due to network issues or slow loading times. Attackers can inject malicious JavaScript code into the onwaiting attribute of a video or audio element. From the attacker's perspective, it is not practical to host valid media content and somehow force it to buffer. Instead, it is much easier to abuse this event handler when the media playback has finished, necessitating a click to replay the media.

```html
<video controls autoplay muted onwaiting=alert(1)><source src=validvideo.mp4 type=video/mp4></*>
```

### onstalled

Another interesting event handler, `onstalled` is triggered when media playback is interrupted due to the browser encountering difficulty in fetching the media resource. This could happen due to various reasons, such as slow network connections or server issues. Developers can utilize this event to execute JavaScript code when playback stalls. Media stalling can be achieved also when the browser attempts to load a resource that is not available. Attackers can specify the invalid media 'src' to point to the unavailable location, which will forcefully trigger the event.

```html
<video controls onstalled=alert()><source src="https://a/1.mp4" type=video/mp4></*>
```

### ondragexit

Firefox supports the `ondragexit` event, which triggers when an element is being dragged out. While not as widely used as other event handlers, `ondragexit` presents a possibility for abuse that requires the victim user to drag the injected element.

```html
<xss draggable="true" ondragexit=alert()>test</*>
```

### Example of usage & abuse: Circumventing AWS Cloudfront Firewall

Web Application Firewalls (WAFs) often employ event handler-based protections as a robust defense mechanism against Cross-site Scripting (XSS) attacks. These protections leverage blocklisting of event handlers, such as onclick or onmouseover, to intercept user inputs before they can be executed by a browser. By monitoring and filtering these events, WAFs can detect and mitigate malicious scripts attempting to exploit vulnerabilities in web applications. This approach adds an additional layer of security, complementing other defensive strategies like input validation and output encoding, to safeguard against XSS threats effectively.

From an attacker's perspective, techniques like fuzzing play a crucial role in attempting to bypass event handler-based protections employed by WAFs to mitigate XSS attacks. Fuzzing involves systematically injecting malformed or unexpected input into web forms or other input fields to discover potential vulnerabilities. By fuzzing, attackers can probe for edge cases or evade detection by crafting input that bypasses WAF rulesets, potentially enabling successful XSS exploitation.

Let's try to fuzz for allowed event handlers on the website that is protected by Amazon's CloudFront WAF like so:

```html
<a FUZZ=b>
```

<img width="966" height="534" alt="Image" src="https://github.com/user-attachments/assets/ecf9dc57-78bc-4df1-84fb-648d23e1a1da" />

This way of testing the WAF ruleset utilizes the HTML `<a>` tag and references JavaScript object `b`, which should not trigger any of the miscellaneous WAF rules.
It is apparent that two event handlers are allowed: `onformdata` and `ondragexit`. Attackers can use them to circumvent the WAF protections and achieve XSS.

### How to defend against modern XSS attacks?

Layered security is paramount in safeguarding against web application attacks due to the increasingly sophisticated nature of cyber threats. By implementing multiple layers of defense mechanisms, organizations can create a robust security posture that significantly reduces the risk of successful breaches. Each layer, whether it's a web application firewall or input filter, adds a barrier that attackers must overcome, making it harder for them to penetrate a system. Moreover, a layered approach ensures that even if one security measure fails or is bypassed, others remain intact, providing a fallback mechanism to mitigate the impact of an attack. 

This multi-tiered strategy not only enhances resilience but also promotes a proactive security culture, where continuous monitoring and adaptation are prioritized to stay ahead of evolving threats. It is important to note, that Web Application Firewall's ruleset can often be circumvented with the introduction of new techniques and features, as HTML and DOM specifications are constantly improving and changing. Because of this, user-input filtering should be regarded as a more important security measure and as a last resort that will protect against most modern data injection attacks. 

Additionally, it is recommended to utilize Content-Security-Policy (CSP) as a last resort, which further protects against XSS attacks and can provide a browser-level security boundary if properly configured.