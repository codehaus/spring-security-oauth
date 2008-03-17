<%@ page import="org.acegisecurity.AuthenticationException" %>
<%@ page import="org.springframework.security.oauth.consumer.OAuthConsumerProcessingFilter" %>
<%@ taglib prefix="authz" uri="http://acegisecurity.org/authz" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jstl/core" %>
<authz:authorize ifAllGranted="ROLE_USER">
  <c:redirect url="index.jsp"/>
</authz:authorize>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
  <link href="<c:url value="/main.css"/>" rel="stylesheet" type="text/css"/>
  <title>tonr</title>
</head>
<body>
<div id="container">
  <div id="navdiv">
    <ul class="mainlinks">
      <li><a href="<c:url value="/index.jsp"/>">home</a></li>
      <authz:authorize ifNotGranted="ROLE_USER">
        <li><a href="<c:url value="/login.jsp"/>">login</a></li>
      </authz:authorize>
      <li><a href="<c:url value="/sparklr/photos.jsp"/>">sparklr pics</a></li>
    </ul>
  </div>
  <div id="content">
    <c:if test="${!empty sessionScope.OAUTH_FAILURE_KEY}">
      <h1>Woops!</h1>

      <p><font color="red">It appears that the OAuth mechanism failed. (<%= ((AuthenticationException) session.getAttribute(OAuthConsumerProcessingFilter.OAUTH_FAILURE_KEY)).getMessage() %>)</font></p>
    </c:if>
    <c:remove scope="session" var="OAUTH_FAILURE_KEY"/>

    <p class="main">Courtesy <a href="http://www.openwebdesign.org">Open Web Design</a> Thanks to <a href="http://www.dubaiapartments.biz/">Dubai Hotels</a></p>
  </div>
</div>
</body>
</html>