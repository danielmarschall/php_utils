<?php

if ($cookie_state == 1)
{
  if (isset($_COOKIE['TestCookie']))
  {
    setcookie('TestCookie', 'test', time());
    echo 'Cookies werden unterst�tzt!';
  }
  else
  {
    echo 'Es werden keine Cookies unterst�tzt!';
  }
}
else
{
  setcookie('TestCookie', 'test');
  header('Location: '.$_SERVER['PHP_SELF'].'?cookie_state=1');
}

?>