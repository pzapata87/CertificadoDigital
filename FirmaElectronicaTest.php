<?php
	require "FirmaElectronica.php";
	require "XML.php";

	$firma_config = ['file'=>dirname(__FILE__).'/20553334919.p12', 'pass'=>'QxMHgjvkCSxXnpUr'];
    $firma = new \sasco\LibreDTE\FirmaElectronica($firma_config);
	
	$xml_data = file_get_contents(dirname(__FILE__) . '/20101015492-01-F100-00000009.xml');
	$firma->signXML($xml_data, '', 'Signature')
?>