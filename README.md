# Security of web apps - frontend and backend
Let's discuss on several sercurity risks and tips on how to pervent them.

### Popular Backend Security Risks and How to Prevent Them

#### 1. Data injection risks
Just as injection attacks can affect your web application's frontend, it's possible to perform injection attacks against your application's backend too.

Attacks can craft queries to your web application's backend, and if there aren't any checks in place to verify the origin of the query, attackers can run commands directly on your backend—which in normal circumstances would have been filtered and blocked by the frontend.

Securing your backend from accepting inputs from non-authorized sources is an effective way to prevent data injection attacks.

#### 2. Lack of authentication security
Web application backends consist of multiple services with authentication requirements, databases as well as console/OS level access have logins, and all of these services run directly on the operating system layer. Therefore, maintaining authentication security is crucial—otherwise, any vulnerability entering the system can lead to the whole operating system being compromised.

For example, when it comes to the web server, restricting logins to certain users or IP addresses, using HTTP authentication on development areas, or using automated brute force detection systems (that automatically ban offending IP addresses) helps a lot.

#### 3. Access control-related misconfigurations
A frequently overlooked aspect of web applications is access control levels, commonly known as ACLs.
ACLs define what parts of a backend a team member or customer can access. Misconfigurations in this area can lead to team members or customers gaining access to sensitive parts of your web application.
Ensuring that your team members and customers have just the right amount of access is important when managing your web application's security.

#### 4. Outdated/end-of-life software components
Multiple software components are used to make any web application work, with web servers, databases and other software helping to improve performance.
With all these bits of software in use, the security of each individual application has to be considered.
For example, if your web server is vulnerable, it can cause your entire web application to be vulnerable—by accepting inputs from users which can expose sensitive areas of your web application.

#### 5. Lack of vulnerability scanning
canning for vulnerabilities is another neglected safeguard regarding web applications, from frontend to backend. Only when you scan will you know what is and isn't vulnerable.
Scanning is often thought of as a difficult and time consuming task, but modern tools have made it possible to scan automatically and with a low amount of effort. Using online vulnerability scanners and other tools like Nikto or OpenVAS helps you stay on top of your web application's safety by automatically scanning and generating reports for you to review.

#### 6. Sensitive data exposure
Applications often cache or hold data in temporary locations for customers to access. This data can be used to improve performance or simply allow users to download their files, but if data isn't removed in time—or isn't restricted to the specific customer—it can allow attackers to find and download this sensitive information.
Securing folders and other publicly accessible information is a must. Also, performing self-scans by using Google Dorks enables you to quickly find public information crawled by search engines.

#### 7. Lack of encryption between frontend and backend
Communication between your web application's frontend and backend is what drives your web application. And this communication often goes over the internet unencrypted, as the software in use is often built without encryption in mind.
Encrypting requests between the frontend and backend is a simple yet critical solution for preventing these attacks.

___
### Common security threats in front-end development
When it comes to security, front-end security is a critical aspect of web development that is often overshadowed by its back-end counterpart. However, overlooking front-end security can leave your web applications vulnerable to a wide range of threats, including cross-site scripting (XSS) attacks, cross-site request forgery (CSRF) attacks, and other security vulnerabilities. 

#### 1. Cross-Site Scripting (XSS) attacks
XSS attacks occur when malicious code is injected into a web application and executed within a user’s browser. This can lead to the theft of sensitive data and other malicious activities.

#### 2. Cross-Site Request Forgery (CSRF) attacks
CSRF attacks involve tricking users into performing actions they didn’t intend to take. Attackers exploit the trust that a website has in a user’s browser to execute unauthorized actions.

#### 3. Injection attacks
Injection attacks, such as SQL injection, involve inserting malicious code into input fields, which can then be executed on the server side, potentially compromising sensitive information.

#### 4. Security risks in external scripts
Third-party libraries and external resources in your web application can introduce security vulnerabilities if not properly vetted.

#### 5. Broken access control
Broken access control occurs when users can access unauthorized areas or perform actions they shouldn’t. It’s a critical security flaw that threatens data confidentiality and application integrity.

### Front-end security best practices

#### 1. Input validation and sanitization
One of the fundamental steps in front-end security is proper input validation and sanitization. User input should not be trusted under any circumstances.

#### 2. Avoid inline scripts
Protecting against inline scripts is vital for front-end security. These scripts pose a significant risk, as they can execute arbitrary code. The best practice is to separate JavaScript from HTML, using external scripts, and implement Content Security Policies (CSPs) to define trusted sources for scripts and resources. By doing so, you create a robust defense against potential XSS attacks and enhance the overall security of your web application.

#### 3. Content Security Policy (CSP)
Using a CSP in front-end security is a proactive measure to mitigate XSS and other code injection attacks. XSS attacks take advantage of the browser being unable to differentiate between legitimate code and malicious code. So instead of blindly letting the browser execute any code a page requests, we are going to filter it based on its source. CSP allows developers to specify which sources of scripts, styles, and other resources are considered trusted within a web application.


#### 4. Secure HTTP requests
When making HTTP requests, ensure they are secure by using HTTPS. HTTPS uses TLS to encrypt HTTP traffic, improving safety and security.

#### 5. Dependency management
Managing software dependencies can be a challenging task, as it involves dealing with external libraries that perform specific functions, and may vary in size and complexity. Dependency management is a technique used to handle these dependencies by identifying, resolving, and patching them in the application’s codebase. It requires careful attention to detail and can be a complex process.

## To Summarize Everything

| Backend Risks      | Frontend Risks           |
| ------------- |:-------------:|
| Data injection risks     | Input validation and sanitization | 
| Lack of authentication security      | Avoid inline scripts      | 
| Access control-related misconfigurations | Content Security Policy (CSP)      
| Lack of vulnerability scanning | Secure HTTP requests      |
| Sensitive data exposure | Dependency management      |
| Outdated/end-of-life software components ||
| Lack of encryption between frontend and backend ||

___
# Let's continue with practical example
In this example, we'll implement Angular 2+ (Current version 18) best security practices 

#### Cross-Site Scripting (XSS) Prevention

```
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

@Component({
  selector: 'app-comment',
  template: `<div [innerHTML]="safeComment"></div>`,
})
export class CommentComponent {
  comment: string = '<script>alert("This is a malicious script!");</script>';
  safeComment: SafeHtml;

  constructor(private sanitizer: DomSanitizer) {
    this.safeComment = this.sanitizer.bypassSecurityTrustHtml(this.comment);
  }
}
```
In this example, the DomSanitizer is used to safely render the user-generated comment, preventing any script injection.

#### Cross-Site Request Forgery (CSRF) Protection
Cross-Site Request Forgery (CSRF) is an attack where a malicious website tricks a user's browser into making unintended requests to a different site. Angular provides built-in protection against CSRF attacks through the use of same-site cookie attributes and tokens.

``` 
import { HttpClient, HttpHeaders } from '@angular/common/http';

@Component({
  selector: 'app-my-component',
  template: '<button (click)="sendRequest()">Send Request</button>',
})
export class MyComponent {
  constructor(private http: HttpClient) {}

  sendRequest() {
    // Generate a CSRF token and include it in the headers
    const csrfToken = 'your-csrf-token';
    const headers = new HttpHeaders({
      'X-CSRF-TOKEN': csrfToken,
    });

    // Send the HTTP request with the CSRF token in the headers
    this.http.get('/api/secure-data', { headers }).subscribe((response) => {
      // Handle the response
    });
  }
} 
```

#### Authentication and Authorization
Here's a simplified example of implementing authentication with Angular using Angular Firebase:
```
import { AngularFireAuth } from '@angular/fire/auth';
import { Router } from '@angular/router';

@Component({
  selector: 'app-login',
  template: `<button (click)="login()">Log In</button>`,
})
export class LoginComponent {
  constructor(private afAuth: AngularFireAuth, private router: Router) {}

  async login() {
    try {
      // Authenticate the user
      const user = await this.afAuth.signInWithEmailAndPassword('user@example.com', 'password');

      // Check user roles and redirect accordingly
      if (user && user.user) {
        if (user.user.emailVerified) {
          this.router.navigate(['/dashboard']);
        } else {
          this.router.navigate(['/verify-email']);
        }
      }
    } catch (error) {
      // Handle authentication errors
    }
  }
}
```
In this example, we use Angular Firebase to handle authentication and route the user based on their email verification status.

#### Secure Communication
Implement a Content Security Policy (CSP) to mitigate the risks of XSS attacks. CSP defines which resources are allowed to be loaded and executed, reducing the chances of malicious script injection.
To configure CSP in Angular, you can add a CSP meta tag to your HTML file:
```
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline';">
```

#### Route Guards for Authorization
Angular provides route guards to protect routes from unauthorized access. 
```
import { Injectable } from '@angular/core';
import { CanActivate, Router } from '@angular/router';
import { AuthService } from './auth.service';

@Injectable({
  providedIn: 'root',
})
export class AuthGuard implements CanActivate {
  constructor(private authService: AuthService, private router: Router) {}

  canActivate(): boolean {
    if (this.authService.isAuthenticated()) {
      return true;
    } else {
      this.router.navigate(['/login']);
      return false;
    }
  }
}
```
In this example, the AuthGuard ensures that only authenticated users can access protected routes.