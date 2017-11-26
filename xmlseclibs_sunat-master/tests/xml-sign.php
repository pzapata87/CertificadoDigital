--TEST--
Basic Signature
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

if (file_exists(dirname(__FILE__) . '/20553334919-01-F100-000000092.xml')) {
    unlink(dirname(__FILE__) . '/20553334919-01-F100-000000092.xml');
}

$doc = new DOMDocument();
$doc->load(dirname(__FILE__) . '/20553334919-01-F100-00000009.xml');

$objDSig = new XMLSecurityDSig();

$objDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);

$objDSig->addReference($doc, XMLSecurityDSig::SHA1, array('http://www.w3.org/2000/09/xmldsig#enveloped-signature'));

$objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type'=>'private'));
$objKey->passphrase = 'QxMHgjvkCSxXnpUr';
/* load private key */
$objKey->loadKey(dirname(__FILE__) . '/20553334919.p12', TRUE);

/* if key has Passphrase, set it using $objKey->passphrase = <passphrase> " */


$objDSig->sign($objKey);

/* Add associated public key */
$objDSig->add509Cert(file_get_contents(dirname(__FILE__) . '/mycert.pem'));




$signatureNode = $doc->documentElement->getElementsByTagName('ExtensionContent')->item(0);
//$signatureNode->parentNode->replaceChild($Signature, $signatureNode);

$objDSig->appendSignature($signatureNode);


$doc->save(dirname(__FILE__) . '/20553334919-01-F100-00000009Test.xml');

// $sign_output = file_get_contents(dirname(__FILE__) . '/sign-basic-test.xml');
// $sign_output_def = file_get_contents(dirname(__FILE__) . '/sign-basic-test.res');
// if ($sign_output != $sign_output_def) {
	// echo "NOT THE SAME\n";
// }
echo "DONE\n";
?>
--EXPECTF--
DONE
