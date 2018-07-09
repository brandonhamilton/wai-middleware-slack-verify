-- | Example slack bot responding that will respond to slash commands
{-# LANGUAGE LambdaCase #-}

import           Data.ByteString.Char8              (pack)
import           Network.Linklater                  (slashSimple)
import           Network.Wai
import           Network.Wai.Handler.Warp           (run)
import           Network.Wai.Middleware.SlackVerify (verifySlackRequest)
import           System.Environment                 (lookupEnv)

main :: IO ()
main = lookupEnv "SLACK_SIGNING_SECRET" >>= \case
    Just secret -> do
        let port = 8080
        putStrLn $ "Running on port " ++ show port
        run port $ verifySlackRequest (pack secret) $ slashSimple $ \_ ->
            pure "👋 "
    Nothing ->
        putStrLn
            $  "Expected 'SLACK_SIGNING_SECRET' environment variable.\n"
            ++ "See https://api.slack.com/docs/verifying-requests-from-slack"
