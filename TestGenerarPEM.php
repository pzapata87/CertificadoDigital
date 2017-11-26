<?php 
$pub_key = openssl_pkey_get_public(file_get_contents('globalsign_sunat.cer')); 
$keyData = openssl_pkey_get_details($pub_key); 
file_put_contents('public_key.pem', $keyData['key']);

$prib_key = openssl_pkey_get_private(file_get_contents('personalsign_sunat.cer')); 
// $keyDataPrib = openssl_pkey_get_details($prib_key); 
// file_put_contents('private_key.pem', $keyDataPrib['key']);

// $certificateCAcer = 'personalsign_sunat.cer';
// $certificateCAcerContent = file_get_contents($certificateCAcer);
// //Convert .cer to .pem, cURL uses .pem 
// $certificateCApemContent =  '-----BEGIN CERTIFICATE-----'.PHP_EOL
    // .chunk_split(base64_encode($certificateCAcerContent), 64, PHP_EOL)
    // .'-----END CERTIFICATE-----'.PHP_EOL;
// $certificateCApem = $certificateCAcer.'.pem';
// file_put_contents($certificateCApem, $certificateCApemContent); 


// personalsign_sunat.cer
$cer_data_pub = file_get_contents('personalsign_sunat.cer');
$cer2pem_pub = cer2pem($cer_data_pub);
file_put_contents('personalsign_sunat.pem', $cer2pem_pub);

// globalsign_sunat.cer
$cer_data_priv = file_get_contents('globalsign_sunat.cer');
$cer2pem_priv = cer2pem($cer_data_priv);
file_put_contents('globalsign_sunat.pem', $cer2pem_priv);

function cer2pem($der_data) {
   $pem = chunk_split(base64_encode($der_data), 64, "\n");
   $pem = "-----BEGIN CERTIFICATE-----\n".$pem."-----END CERTIFICATE-----\n";
   return $pem;
}

?>