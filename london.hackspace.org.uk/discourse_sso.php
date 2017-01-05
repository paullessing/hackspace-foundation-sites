<?php require_once( $_SERVER['DOCUMENT_ROOT'] . '/../lib/init.php');

$ssoPayload = fRequest::get('sso', 'string');
$ssoSignature = fRequest::get('sig', 'string');
if (empty($ssoPayload) || empty($ssoSignature)) {
    die('Empty payload or empty sig');
    fURL::redirect('/');
}
$rawPayload = base64_decode($ssoPayload, true);
if (empty($rawPayload)) {
    die('Payload did not decode');
    fURL::redirect('/');
}
$payloadData = array();
parse_str($rawPayload, $payloadData);
$nonce = $payloadData['nonce'];
if (empty($nonce)) {
    die('Payload did not contain nonce');
}

// ensure signature and payload are valid
$expectedSig = hash_hmac('sha256', $rawPayload, $DISCOURSE_SSO_SECRET);
if (strcmp($expectedSig, $ssoSignature) !== 0) {
    var_dump($rawPayload);
    var_dump($expectedSig);
    die('Invalid signature');
}

echo "<p>SSO: '" . $rawPayload . "'</p>";
echo "<p>SIG: '" . $ssoSignature . "'</p>";

if (!$user) {
    fURL::redirect('/login.php?forward=' . urlencode('/discourse_sso.php?sso=' . $ssoPayload . '&sig=' . $ssoSignature));
}

$ssoResultData = array(
    'nonce' => $nonce,
    'email' => $user->getEmail(),
    'require_activation' => 'true', // Because our emails are not validated
    'external_id' => $user->getMemberNumber(),
    'username' => $user->getFullName(),
    'name' => $user->getFullName()
);
if ($user->isAdmin()) {
    $ssoResultData['moderator'] = 'true';
}

$returnPayload = base64_encode(http_build_query($ssoResultData));
$returnSignature = hash_hmac('sha256', $returnPayload, $DISCOURSE_SSO_SECRET);

$returnParams = http_build_query(array(
    'sso' => $returnPayload,
    'sig' => $returnSignature
));

echo '<pre>';
var_dump($ssoResultData);
echo '</pre>';
echo '<pre>';
var_dump($returnPayload);
var_dump($returnSignature);
echo '</pre>';

$redirectUrl = $DISCOURSE_URL . '/session/sso_login?' . $returnParams;

die('Redirecting to: <code>' . $redirectUrl . '</code>');
fURL::redirect($redirectUrl);

