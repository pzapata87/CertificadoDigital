<?php
require_once "sunatSoap.php";

$ublfile='20553334919-01-F100-00000009.xml';
// $privatekeyfile='personalsign_sunat.cer';//file_get_contents('personalsign_sunat.cer');
// $publickeyfile='globalsign_sunat.cer';//file_get_contents('globalsign_sunat.cer');

$s=new sunatSoap($ublfile);
$s->setLoginInfo("20523625633","MODDATOS","MODDATOS");
$resp=$s->submitToSunat();
var_dump($resp);
?>