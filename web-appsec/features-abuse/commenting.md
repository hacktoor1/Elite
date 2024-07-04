# Commenting

* <pre class="language-bash"><code class="lang-bash"><strong>[] Change the email of th request to registered email in target 
  </strong><strong>[] Change email to un registered email in the target and then register with it
  </strong><strong>[] Change the ID one number or the whole id with another user ID     
  </strong></code></pre>
*   [ ] **DOM Clobbering**

    We can therefore cause the JavaScript references to return an empty object using the following technique:

    ```bash
    <img id="getElementById">
    <img id="querySelector">
    <img id="getElementByTagName">
    ```

    Which now returns the following output in our console: Uncaught TypeError: `document.getElementById is not a function at ….`
*
[ ] 
    ```bash
    assuming an application uses a BBcode tag to publish image:
    [img width="100" height="50"]<https://www.bbcode.org/images/lubeck_small\\.jpg\\[/img]>

    Which is interpreted in the browser as follows:
    <img width="100" height="50" src=”https://www.bbcode.org/images/lubeck_\\small.jpg”>

    We can take advantage of DOM clobbering like this:
    [img width="100" id=”getElementById” height="50"]<https://www.bbcode.org>\\/images/lubeck_small.jpg\\[/img]

    We have now effectively clobbered the DOM in the web application, which may
    result in the breakdown of functionality and in some cases cause the browser to
    become unresponsive
    ```

Markup Language? try [**Create A picture that steals Data**](https://medium.com/@iframe\_h1/a-picture-that-steals-data-ff604ba1012)

*   ```bash
    Go to <https://iplogger.org/>
    choose invisible image 
    send the comment
    ```

    **\[\[IDOR|IDOR]]to Read any other's comments**
*
[ ] 
    1. Search for any fields/forms that you cant see others comments
    2. Analyze the traffic
    3. change identifier to user B and u can see user b comments
    4.
    5. **Race Condition**
       1. Unlimited Comments on a thread
       2. Suppose a user can comment only once, try race conditions here to see if multiple comments are possible.
    6.
    7. **Privilege Escalation**
       * Suppose there is an option: comment by the verified user (or some privileged user) try to tamper with various parameters in order to see if you can do this activity.

    > **Thread Comment Functionality**

    *
    * [ ] Unlimited Comments on a thread
    *
    * [ ] Suppose a user can comment only once, try race conditions here to see if multiple comments are possible.
    *
    * [ ] Suppose there is an option: comment by the verified user (or some privileged user) try to tamper with various parameters in order to see if you can do this activity.
    *

    Try posting comments impersonating some other users.
