-----------------------------------------------------------------------------
-- |
-- Module      : Network.Wai.Middleware.SlackVerify
-- Description : WAI Slack request verification Middleware
-- Copyright   : (c) 2018 Brandon Hamilton
-- License     : MIT
-- Maintainer  : Brandon Hamilton <brandon.hamilton@gmail.com>
--
-- Middleware for WAI that uses signed secrets to verify Slack requests.
-- See <https://api.slack.com/docs/verifying-requests-from-slack>
--

module Network.Wai.Middleware.SlackVerify 
    ( verifySlackRequest
    , verifySlackRequest'
    , VerificationFailure(..)
    , FailureResponse
    , SigningSecret
    ) where

import           Control.Error.Util
import           Crypto.Hash
import           Crypto.Hash.Algorithms  (SHA256)
import           Crypto.MAC.HMAC         (HMAC(..), hmac)
import           Data.ByteArray.Encoding (convertToBase, Base(Base16))
import           Data.ByteString         (ByteString)
import qualified Data.ByteString         as BS
import qualified Data.ByteString.Char8   as BC
import           Data.IORef              (newIORef, atomicModifyIORef)
import           Network.HTTP.Types      (status403)
import           Network.Wai

-- Create a copy of the request body 
-- Based on technique from
-- https://github.com/yesodweb/wai/blob/master/wai-extra/Network/Wai/Middleware/RequestLogger.hs
getRequestBody :: Request -> IO (Request, BC.ByteString)
getRequestBody req = do
    let loop front = do
            bs <- requestBody req
            if BC.null bs then return $ front [] else loop $ front . (bs :)
    body    <- loop id
    ichunks <- newIORef body
    let rbody = atomicModifyIORef ichunks $ \chunks -> case chunks of
            []    -> ([], BC.empty)
            x : y -> (y, x)
    let req' = req { requestBody = rbody }
    return (req', BC.concat body)

-- | Verification Failure reasons
data VerificationFailure
    = NoSignature
    -- ^ The request does not contain the relevant
    -- signature headers
    | SignatureMismatch
    -- ^ Signature of the request does not match
    -- the server generated signature
    deriving Show

type FailureResponse = VerificationFailure -> Application

type SigningSecret = ByteString

defaultFailureResponse :: FailureResponse
defaultFailureResponse f _ res =
    res $ responseLBS status403 [] "Invalid Signature"

-- | Middleware that will verify an incoming slack request signature
-- using the provided signing secret.
verifySlackRequest :: SigningSecret -> Middleware
verifySlackRequest secret app = verifySlackRequest' secret defaultFailureResponse app

-- | Middleware that will verify an incoming slack request signature
-- using the provided signing secret. The failure response handler
-- will be called upon verification errors.
verifySlackRequest' :: SigningSecret -> FailureResponse -> Middleware
verifySlackRequest' secret onFailure app req res = do
    (req', payload) <- getRequestBody req
    case checkSignature payload of
        Left  e -> onFailure e req' res
        Right _ -> app req' res
  where
    headers   = requestHeaders req
    timestamp = note NoSignature (lookup "X-Slack-Request-Timestamp" headers)
    signature = note NoSignature (lookup "X-Slack-Signature" headers)
    checkSignature p = do
        t <- timestamp
        s <- signature
        let HMAC h =
                hmac secret $ (BS.concat ["v0", ":", t, ":", p]) :: HMAC SHA256
        if s == BS.append "v0=" (convertToBase Base16 h)
            then Right ()
            else Left SignatureMismatch
