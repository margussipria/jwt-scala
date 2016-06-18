package controllers

import _root_.play.api.mvc.{Result, Results}
import _root_.play.api.test.Helpers._
import _root_.play.api.test.{FakeApplication, FakeRequest}
import org.scalatestplus.play.{OneAppPerSuite, PlaySpec}

import scala.concurrent.Future

class ApplicationHmacBase64KeySpec extends PlaySpec with OneAppPerSuite with Results {

  implicit override lazy val app: play.api.Application = FakeApplication(additionalConfiguration = Map(
    "eu.sipria.play.jwt.algorithm" -> "HS256",
    "eu.sipria.play.jwt.key.type" -> "HMAC",
    "eu.sipria.play.jwt.key.base64" -> "true",
    "eu.sipria.play.jwt.key.hmac.secret" -> "1kHndxh2zXTK701QKx6B_CkzEu-orMR-TpvJXvlrjXg7maLf_1B7yegplt3EW9Mp",

    "eu.sipria.play.jwt.options.expiration" -> "false"
  ))
  val Header = "Authorization"

  "Application" should {
    val controller = new Application

    "login user named pepper correctly" in {

      val authorization: String = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjp7ImlkIjoxLCJuYW1lIjoiUGF1bCJ9LCJuYW1lIjoiTWF0dGhldyBTY2hhcmxleSIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vLVhkVUlxZE1rQ1dBL0FBQUFBQUFBQUFJL0FBQUFBQUFBQUFBLzQyNTJyc2NidjVNL3Bob3RvLmpwZyIsImVtYWlsIjoibWF0dGhldy5zY2hhcmxleUBlcXVpZW0uY29tLmF1IiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImFwcF9tZXRhZGF0YSI6eyJhdXRob3JpemF0aW9uIjp7Imdyb3VwcyI6WyJEYXRhYmFzZSBTZXJ2ZXIgQWNjZXNzIl19LCJwZ3BfcHVibGljX2tleXMiOlsiMjU2MTk3RTU5REVBNTY2RjI0MDAyMkQyRUI2MDM3NTM1NDFGREYzRiIsIkZEQjRGNjJFMjM2NzBEQTEwREU4QjdEQTZFRTQ0OTlFNDM1RkE1MkIiXX0sImlzcyI6Imh0dHBzOi8vZXF1aWVtLmF1LmF1dGgwLmNvbS8iLCJzdWIiOiJnb29nbGUtb2F1dGgyfDExNTQ2MzM0MDE5ODc5NzI4MDUzNyIsImF1ZCI6ImFMcEdJUFFvRWdhb1N3QlpFTEhwS3Y4aHZySlFYNFRUIiwiZXhwIjoxNDY0MTgwNDA1LCJpYXQiOjE0NjQxNzY4MDV9.TVsgpsFAHXSGXLDhEfjP1qqE1ob2hotQSh5klXNGg0s"

      val authenticatedRequest = FakeRequest().withHeaders(Header -> authorization)

      val publicApiResult: Future[Result] = controller.publicApi().apply(authenticatedRequest)
      status(publicApiResult) must equal(OK)
      header(Header, publicApiResult) must be(empty)

      val privateApiResult: Future[Result] = controller.privateApi().apply(authenticatedRequest)
      status(privateApiResult) must equal(OK)
      header(Header, privateApiResult) must be(defined)

      val adminApiResult: Future[Result] = controller.adminApi().apply(authenticatedRequest)
      status(adminApiResult) must equal(FORBIDDEN)
      header(Header, adminApiResult) must be(defined)
    }
  }
}
