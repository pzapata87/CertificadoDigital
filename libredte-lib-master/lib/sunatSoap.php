<?php
require "FirmaElectronica.php";
require "XML.php";
	
class sunatSoap{

	//Webservice URLs
	var $soap_url_prod="";//https://www.sunat.gob.pe:443/ol-ti-itcpfegem/billService";//SUNAT server production
	var $soap_url_test="https://e-factura.sunat.gob.pe/ol-ti-itcpfegem/billService?wsdl";//SUNAT server test
	var $soap_url_acc="https://www.sunat.gob.pe:443/ol-ti-itcpgem-sqa/billService?wsdl";//SUNAT acceptance server
	
	//File
	var $filename=null;
	var $filenameZipped=null;
	
	//create soap request for SUNAT and submit
	function __construct($ublFileName){
		$this->filename=$ublFileName;
	}

	function setLoginInfo($ruc,$username,$password){
		$this->username=$ruc.$username;//RUC + username
		$this->password=$password;
	}
	
	private function signUBL(){
		$firma_config = ['file'=>dirname(__FILE__).'/20553334919.p12', 'pass'=>'QxMHgjvkCSxXnpUr'];
		$firma = new \sasco\LibreDTE\FirmaElectronica($firma_config);

		$xmlName = dirname(__FILE__) . '/'.$this->filename;
		$firma->signXML($xmlName);
		//$firma->verifyXML($xmlName);
	}
	
	private function createZipFile(){
		$pInfo=pathinfo($this->filename);
		$this->filenameZipped=$pInfo['dirname']."/".$pInfo['filename'].".zip";
		$zip=new ZipArchive();
		$zip->open($this->filenameZipped,ZIPARCHIVE::CREATE);
		$zip->addFile($this->filename,$pInfo['basename']);
		$zip->close();
	}	
	
	function submitToSunat(){
		$this->signUBL();
		$this->createZipFile();
		$url=$this->soap_url_test;
		$wsse_header=new WsseAuthHeader($this->username,$this->password);
		$c=new SoapClient($url,array("trace"=>true));
		$c->__setSoapHeaders(array($wsse_header));
		$p=array('fileName'=>$this->filenameZipped,"contentFile"=>file_get_contents($this->filenameZipped));
		
		try{
			$obj=$c->sendBill($p);
			return $obj->applicationResponse;
		}catch(SoapFault $f){
			return array(false,$f->faultcode,$f->faultstring);
		}
	}
}
class WsseAuthHeader extends SoapHeader {

	private $wss_ns = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';

	function __construct($user, $pass, $ns = null) {
		if ($ns) {
			$this->wss_ns = $ns;
		}

		$auth = new stdClass();
		$auth->Username = new SoapVar($user, XSD_STRING, NULL, $this->wss_ns, NULL, $this->wss_ns);
		$auth->Password = new SoapVar($pass, XSD_STRING, NULL, $this->wss_ns, NULL, $this->wss_ns);

		$username_token = new stdClass();
		$username_token->UsernameToken = new SoapVar($auth, SOAP_ENC_OBJECT, NULL, $this->wss_ns, 'UsernameToken', $this->wss_ns);

		$security_sv = new SoapVar(
				new SoapVar($username_token, SOAP_ENC_OBJECT, NULL, $this->wss_ns, 'UsernameToken', $this->wss_ns), 
			SOAP_ENC_OBJECT, NULL, $this->wss_ns, 'Security', $this->wss_ns);
		parent::__construct($this->wss_ns, 'Security', $security_sv, true);
	}
}
?>