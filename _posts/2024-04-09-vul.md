---
title: "How the Web works"
datePublished: Sat Feb 10 2024 18:28:06 GMT+0000 (Coordinated Universal Time)
cuid: cm8slnv4d001k09la2f1x0tmm
slug: how-the-web-works-1a798b382b42

---

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1743155305477/4b139dd6-8b5b-48d6-9942-821789498d69.jpeg)

Ever wondered what happens when you visit a Website or enter a URL? Well, look no further. I’ll be breaking down what happens when you enter a URL into your browsers here.

### Extracting the Domain Name

Once you enter a URL in your browser (e.g http://www.google.com/), your browser determines the domain name from the URL. A domain name which must contain only alphanumeric characters and underscore, indentifies which website you're trying to visit. This domain name serves as a way to identify an online address

### Resolving an IP Address

After the domain name is determined, your browser uses IP(Internet Protocol) to look up the IP address associated with the domain you entered. This look up process is referred to as RESOLVING THE IP ADDRESS, and it’s a must do process for every domain on the Internet to resolve to an IP address inorder to function.  
To look up an IP address using just the domain name, your computer sends a request to Domain Name System (DNS) servers that consist of specialized servers on the internet and have a registry of all domains and their matching IP addresses.

### Establishing a TCP Connection

The computer attempts to establish a Transmission Control Protocol (TCP) connection with the resolved IP address on port 80 (due to http:// visited) or 443 (for https://). TCP provides a two-way communication so that message recipients can verify the information they receive and nothing is lost in transmission. The server you’re sending requests to might have multiple servers running so it uses port(server doors) to identify specific processes to receive requests.

### Sending an HTTP Request

Using the URL (http://www.google.com) as an example

➊ GET / HTTP/1.1  
➋ Host: www.google.com  
➌ Connection: keep-alive  
➍ Accept: application/html, \*/\*  
➎ User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36  
(KHTML, like Gecko) Chrome/72.0.3626.109 Safari/537.36  
  

The browser makes a GET (just retrieves information) request to the / path ➊. The host header ➋ holds an additional piece of information that is sent as part of the request. HTTP 1.1 needs it to identify  
where a server at the given IP address should send the request because IP addresses can host multiple domains. A connection header ➌ indicates the request to keep the connection with the server open to avoid the overhead of constantly opening and closing connections. Response format at ➍ is expected is expected application/html but will accept any format, as indicated by the wildcard (\*/\*). Finally the User-Agent ➎ denotes the software responsible for sending the request.

### Server Response

The server response should look like:

➊ HTTP/1.1 200 OK  
➋ Content-Type: text/html  
<html>  
<head>  
 <title>Google.com</title>  
</head>  
<body>  
➌ --snip--  
 </body>  
</html>  
  

An http response with status code 200 OK is received in ➊, the status code is important because it indicates how the server is responding. An HTTP message body is the text associated with a request or response ➌ in which the content have been removed and replaced with --snip-- because of how big the response body from Google is. The Content-Type header ➋ informs the browsers of the body’s media type. The media type determines how a browser will render body contents.

### Rendering the Response

In the example above the sever sent a status code of 200 OK in response with text/html which will make our browser to begin rendering the contents it received. The response’s body tells the browser what should be presented to the user.

Now you should have a basic understanding on what occurs within your browser when an HTTP/URL request is sent, how the browser responds to this request and render your required information.

Thanks for reading 😌.