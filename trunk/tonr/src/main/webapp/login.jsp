<%@ page import="org.acegisecurity.ui.AbstractProcessingFilter" %>
<%@ page import="org.acegisecurity.AuthenticationException" %>
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
      <li><a href="<c:url value="/login.jsp"/>"  class="selected">login</a></li>
      <li><a href="<c:url value="/sparklr/photos.jsp"/>">sparklr pics</a></li>
    </ul>
  </div>
  <div id="content">
    <c:if test="${!empty sessionScope.ACEGI_SECURITY_LAST_EXCEPTION}">
      <h1>Woops!</h1>

      <p><font color="red">Your login attempt was not successful. (<%= ((AuthenticationException) session.getAttribute(AbstractProcessingFilter.ACEGI_SECURITY_LAST_EXCEPTION_KEY)).getMessage() %>)</font></p>
    </c:if>
    <c:remove scope="session" var="ACEGI_SECURITY_LAST_EXCEPTION"/>

    <authz:authorize ifNotGranted="ROLE_USER">
      <h1>Login</h1>

      <p>Tonr.com has only two users: "marissa" and "sam".  The password for "marissa" is password is "wombat" and for "sam" is password is "kangaroo".</p>

      <form action="<c:url value="/login.do"/>" method="POST">
        <p class="formtext">Username: <input type='text' name='j_username' value="marissa"></p>
        <p class="formtext">Password: <input type='text' name='j_password' value="wombat"></p>
        <p class="formtext"><input name="login" value="login" type="submit"></p>
      </form>
    </authz:authorize>

    <p class="main">Courtesy <a href="http://www.openwebdesign.org">Open Web Design</a> Thanks to <a href="http://www.dubaiapartments.biz/">Dubai Hotels</a></p>
  </div>
</div>
</body>
</html>