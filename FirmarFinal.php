<?php	
	require 'xmlseclibs-master/xmlseclibs.php';
	use RobRichards\XMLSecLibs\XMLSecurityDSig;
	use RobRichards\XMLSecLibs\XMLSecurityKey;	
	
	//require(dirname(__FILE__) . '/xmlseclibs-master/xmlseclibs.php');
	//use XMLSecurityDSig;
	//return false;
	$ReferenceNodeName = 'ExtensionContent';
	$privateKey = file_get_contents(dirname(__FILE__).'/personalsign_sunat.pem');//'/private_key.pem');
	$publicKey = file_get_contents(dirname(__FILE__).'/globalsign_sunat.pem');//'/public_key.pem');
	$xmlstr = file_get_contents("20101015492-01-F100-00000009.xml");
	$domDocument = new DOMDocument();
	//$domDocument->loadXML($xmlstr);
	echo(dirname(__FILE__) . '/20101015492-01-F100-00000009.xml');
	$xml = "<ApplicationRequest xmlns=\"http://example.org/xmldata/\"><CustomerId>12345678</CustomerId><Command>GetUserInfo</Command><Timestamp>1317032524</Timestamp><Status>ALL</Status><Environment>DEVELOPMENT</Environment><SoftwareId>ExampleApp 0.1\b</SoftwareId><FileType>ABCDEFG</FileType></ApplicationRequest>"; 
	//$domDocument->load(dirname(__FILE__) . '/20101015492-01-F100-00000009.xml');
	
	X509Certificate2 certificate = new X509Certificate2(dirname(__FILE__).'/personalsign_sunat.cer');
	echo(certificate.HasPrivateKey);
	
	
	$domDocument->formatOutput = false; 
	$domDocument->preserveWhiteSpace = false;
	$domDocument->loadXML($xml);
	$ruc = '20314514697';
	
	//$objSign = new \FR3D\XmlDSig\Adapter\XmlseclibsAdapter();
	//$objSign = new \FR3D\XmlDSig\Adapter\XmlseclibsAdapter();
	
	$objSign = new XMLSecurityDSig();
	// Use the c14n exclusive canonicalization
	$objSign->setCanonicalMethod(XMLSecurityDSig::C14N);
	// Sign using SHA-256
	$objSign->addReference(
		$domDocument, 
		XMLSecurityDSig::SHA1, 
		array('http://www.w3.org/2000/09/xmldsig#enveloped-signature'),
		$options = array('force_uri' => true)
	);
	
	$objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type'=>'private'));
	// Load the private key
	//$objKey->loadKey($privateKey, false, true);
	$objKey->loadKey(dirname(__FILE__).'/personalsign_sunat.pem', TRUE);
	
	/* 
	If key has a passphrase, set it using 
	$objKey->passphrase = '<passphrase>';
	*/
	// Sign the XML file
	//echo($domDocument->getElementsByTagName($ReferenceNodeName)->item(1)->nodeValue);
	$objSign->sign($objKey, $domDocument->documentElement);
	//$objSign->signData($domDocument->getElementsByTagName($ReferenceNodeName)->item(1));
	//$objSign->sign($objKey, $domDocument->getElementsByTagName($ReferenceNodeName)->item(1));
	// Add the associated public key to the signature
	$objSign->add509Cert($publicKey);
	
	// Append the signature to the XML
	//$objSign->appendSignature($domDocument->getElementsByTagName($ReferenceNodeName)->item(0));//$ReferenceNodeName);
	
	//$domDocument->save(dirname(__FILE__) . '/sign-c14-comments.xml');
	//$content = $domDocument->saveXML();
?>