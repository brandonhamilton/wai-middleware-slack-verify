module WaiMiddlewareSlackVerifySpec
    ( spec
    ) where

import           Crypto.Hash
import           Crypto.Hash.Algorithms
import           Crypto.MAC.HMAC
import           Data.ByteArray.Encoding (convertToBase, Base(Base16))
import           Data.ByteString                 (ByteString)
import qualified Data.ByteString                 as BS
import qualified Data.ByteString.Char8           as BC
import           Data.Time.Clock.POSIX
import           Test.Hspec
import           Test.HUnit                      hiding (Test)
import           Network.Wai
import           Network.Wai.Test
import           Network.Wai.Middleware.SlackVerify
import           Network.HTTP.Types

spec :: Spec
spec = describe "Network.Wai.Middleware.SlackVerify" $ do
    it "authenticates valid signatures" caseValidSignature
    it "rejects missing signature"      caseMissingSignature
    it "rejects signature mismatch"     caseSignatureMismatch

testApp :: ByteString -> FailureResponse -> Application
testApp secret h =
    verifySlackRequest' secret h $ \_ f -> f $ responseLBS status200 [] ""

testSecret = "<RANDOM SECRET>"

testHandler e _ res = res $ responseLBS status403 [] msg
  where
    msg = case e of
        NoSignature       -> "No signature"
        SignatureMismatch -> "Signature Mismatch"

createHeaders :: ByteString -> ByteString -> [(HeaderName, ByteString)]
createHeaders sig timestamp =
    [ ("Content-Type"             , "application/json")
    , ("X-Slack-Request-Timestamp", timestamp)
    , ("X-Slack-Signature"        , sig)
    ]

getTimestamp :: IO ByteString
getTimestamp = BC.pack . show . floor <$> getPOSIXTime

caseValidSignature :: Assertion
caseValidSignature = do
    timestamp <- getTimestamp
    flip runSession (testApp testSecret testHandler) $ do
        res <- request defaultRequest
            { requestHeaders = createHeaders (generateSignature timestamp)
                                             timestamp
            }
        assertStatus 200 res
        assertBody   ""  res
  where
    generateSignature t =
        let
            HMAC h =
                hmac testSecret $ (BS.concat ["v0", ":", t, ":", ""]) :: HMAC SHA256
        in  BS.append "v0=" (convertToBase Base16 h)

caseMissingSignature :: Assertion
caseMissingSignature = do
    flip runSession (testApp testSecret testHandler) $ do
        res <- request defaultRequest
        assertStatus 403            res
        assertBody   "No signature" res

caseSignatureMismatch :: Assertion
caseSignatureMismatch = do
    timestamp <- getTimestamp
    flip runSession (testApp testSecret testHandler) $ do
        res <- request defaultRequest
            { requestHeaders = createHeaders "<invalid>" timestamp
            }
        assertStatus 403                  res
        assertBody   "Signature Mismatch" res
