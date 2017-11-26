<?php

	require_once __DIR__ . '/../src/XmlDigitalSignature.php';

	$dsig = new XmlDsig\XmlDigitalSignature();

	$dsig
		->setCryptoAlgorithm(XmlDsig\XmlDigitalSignature::RSA_ALGORITHM)
		->setDigestMethod(XmlDsig\XmlDigitalSignature::DIGEST_SHA1)
		->forceStandalone();

	// load the private and public keys
	try
	{
		$dsig->loadPrivateKey(__DIR__ . '/keys/20553334919.p12', 'QxMHgjvkCSxXnpUr');		
		// $dsig->loadPublicKey(__DIR__ . '/keys/20553334919.cer');
		// $dsig->loadPublicXmlKey(__DIR__ . '/keys/20553334919-01-F100-00000009.xml');
	}
	catch (\UnexpectedValueException $e)
	{
		print_r($e);
		exit(1);
	}

	try
	{
		$dsig->addObject('Lorem ipsum dolor sit amet');
		$dsig->sign();
		$dsig->verify();
	}
	catch (\UnexpectedValueException $e)
	{
		print_r($e);
		exit(1);
	}

	var_dump($dsig->getSignedDocument());