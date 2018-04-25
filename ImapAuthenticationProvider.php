<?php
/**
 * MIT License
 * Copyright (c) 2018 Alphanoob1337
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following
 * conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all copies
 * or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
 * CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
 * OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/**
 * This is the main code file for the ImapAuthentiction extension for MediaWiki.
 * The extension provides user authentication checks against an e-mail server. More
 * precisely against an IMAP and SMTP server.
 */


// A few imports from the WikiMedia core.
use MediaWiki\Auth\AbstractPrimaryAuthenticationProvider ;
use MediaWiki\Auth\PasswordAuthenticationRequest;
use MediaWiki\Auth\AuthenticationRequest;
use MediaWiki\Auth\AuthenticationResponse;
use MediaWiki\Auth\AuthManager;

/**
 * The class ImapAuthenticationProvider is an implementation of the
 * AbstractPrimaryAuthenticationProvider.
 */
class ImapAuthenticationProvider extends AbstractPrimaryAuthenticationProvider  {

    /**
     * Of the requests returned by this method, exactly one should have
     * MediaWiki\Auth\AuthenticationRequest::$required set to REQUIRED.
     * @param MediaWiki\Auth\AuthManager $action
     * @param array $options
     * @return array Returns array of AuthenticationRequest that can be processed.
     */
    public function getAuthenticationRequests( $action, array $options ) {
        switch ( $action ) {
            case AuthManager::ACTION_LOGIN:
                return [ new PasswordAuthenticationRequest() ];
            default:
                return [];
        }
    }

    /**
     * Of the requests returned by this method, exactly one should have
     * MediaWiki\Auth\AuthenticationRequest::$required set to REQUIRED.
     * @param string $username Username to check.
     * @param int $flags Bitfield of User:READ_* constants
     * @return bool Returns true if the username exists on the SMTP server. Else returns
     *  false.
     */
    public function testUserExists( $username, $flags = User::READ_NORMAL ) {
        $username = User::getCanonicalName( $username, 'usable' );
        
        if ( $username === false ) {
            return false;
        } else {
            global $wgImapAuthorizationSmtpServerAddress;
            global $wgImapAuthorizationSmtpServerPort;

            // Open socket to the SMTP server
            $fp = fsockopen($wgImapAuthorizationSmtpServerAddress, 
                $wgImapAuthorizationSmtpServerPort, $errno, $errstr, 30);
            if ( $fp ) {
                // Check if welcome message is 220
                $line = fgets($fp, 4096);
                $res = (substr($line, 0, 3) == '220');
                
                // Send HELO command
                $out = "helo hi\r\n";
                fwrite($fp, $out);
                
                // Check if response message is 250
                $line = fgets($fp, 4096);
                $res &= (substr($line, 0, 3) == '250');
                
                /* Send a fake sender address; since there will be no mail sent, this
                    is not important*/
                $out = "mail from: <user@request.com>\r\n";
                fwrite($fp, $out);
                
                // Check if response message is 250
                $line = fgets($fp, 4096);
                $res &= (substr($line, 0, 3) == '250');
                
                // Send recipient name
                $out = "rcpt to: <$username>\r\n";
                fwrite($fp, $out);
                
                // Check if response message is 250
                $line = fgets($fp, 4096);
                $exists = (substr($line, 0, 3) == '250');
                
                // Send QUIT command and close socket
                $out = "quit\r\n";
                fwrite($fp, $out);
                fclose($fp);
                if (!$res) {
                    return false;
                } else {
                    return $exists;
                }
            }
            return true;
        }
    }
    
    /**
     * Validate a change of authentication data (e.g. passwords). Since this
     * AbstractPrimaryAuthenticationProvider does not support changes, it always returns
     * StatusValue::newGood( 'ignored' )
     * @param MediaWiki\Auth\AuthenticationRequest $req Request type. Ignored.
     * @param bool $checkData Should the credentials be verified? Ignored.
     * @return StatusValue StatusValue::newGood( 'ignored' )
     */
    public function providerAllowsAuthenticationDataChange(	AuthenticationRequest $req,
        $checkData = true ) {
        return StatusValue::newGood( 'ignored' );
    }

    /**
     * This function should never be called: providerAllowsAuthenticationDataChange with
     * $checkData = true was called before this one and StatusValue::newGood( 'ignored' )
     * is returned.
     * @param MediaWiki\Auth\AuthenticationRequest $req Request type. Ignored.
     */
    public function providerChangeAuthenticationData( AuthenticationRequest $req ) {}

    /**
     * This AbstractPrimaryAuthenticationProvider does not provide account creation,
     * so self::TYPE_NONE is always returned.
     * @return int self::TYPE_NONE
     */
    public function accountCreationType() {
        return self::TYPE_NONE;
    }

    /**
     * This AbstractPrimaryAuthenticationProvider does not provide account creation,
     * so AuthenticationResponse::newAbstain() is always returned.
     * @param User $user
     * @param User $creator
     * @param AuthenticationRequest[] $reqs
     * @return MediaWiki\Auth\AuthenticationResponse AuthenticationResponse::newAbstain()
     */
    public function beginPrimaryAccountCreation( $user, $creator, array $reqs ) {
        return AuthenticationResponse::newAbstain();
    }

    /**
     * This is the main authentication mechanisms. It tries to log into the configured
     * IMAP server. If the authentication fails, Abstain is returned. Else pass.
     * This requires the imap PHP module to be installed.
     * @param AuthenticationRequest[] $reqs The login request(s).
     * @return MediaWiki\Auth\AuthenticationResponse either abstain or pass.
     */
    public function beginPrimaryAuthentication( array $reqs ) {
        // Get credentials
        $req = AuthenticationRequest::getRequestByClass( $reqs, PasswordAuthenticationRequest::class );
        if ( !$req ) {
            return AuthenticationResponse::newAbstain();
        }
        
        if ( $req->username === null || $req->password === null ) {
            return AuthenticationResponse::newAbstain();
        }
        
        $username = User::getCanonicalName( $req->username, 'usable' );
        if ( $username === false ) {
            return AuthenticationResponse::newAbstain();
        } else {
            // Start checking the credentials
            global $wgImapAuthorizationImapServerAddress;
            global $wgImapAuthorizationImapServerPort;
            global $wgImapAuthorizationImapServerEnforceSsl;
            global $wgImapAuthorizationImapServerEnforceTls;
            global $wgImapAuthorizationImapServerVerifyCert;

            $connstr = '{' . $wgImapAuthorizationImapServerAddress . ':' . $wgImapAuthorizationImapServerPort . '}/imap';
            if ($wgImapAuthorizationImapServerEnforceSsl) {
                $connstr .= '/ssl';
            } else if ($wgImapAuthorizationImapServerEnforceTls) {
                $connstr .= '/tls';
            }

            if ($wgImapAuthorizationImapServerVerifyCert) {
                $connstr .= '/validate-cert';
            } else {
                $connstr .= '/novalidate-cert';
            }

            // Opening the IMAP connection
            $mbox = imap_open($connstr, $username, $req->password, OP_HALFOPEN);
            if ($mbox === false) {
                return AuthenticationResponse::newAbstain();
            } else {
                // Successfull check!
                imap_close($mbox);
                return AuthenticationResponse::newPass( $username );
            }
        }
    }
}