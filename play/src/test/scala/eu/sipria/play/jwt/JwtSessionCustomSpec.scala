package eu.sipria.play.jwt

import akka.stream.Materializer
import eu.sipria.jwt.JwtHeader
import eu.sipria.jwt.algorithms.JwtAlgorithm
import org.scalatest._
import org.scalatestplus.play._
import play.api.Application
import play.api.libs.json._
import play.api.test.Helpers._
import play.api.test._

class JwtSessionCustomSpec extends PlaySpec with OneAppPerSuite with BeforeAndAfter with PlayFixture {
  val materializer: Materializer = app.materializer

  // Just for test, users shouldn't change the header name normally
  def HEADER_NAME = "Auth"
  def sessionTimeout = 10

  implicit var jwtTime = mockTime(validTime)

  implicit override lazy val app: Application = FakeApplication(
    additionalConfiguration = Map(
      "play.crypto.secret" -> secretKey,
      "play.http.session.jwtName" -> HEADER_NAME,
      "play.http.session.maxAge" -> sessionTimeout * 1000, // 10sec... that's really short :)
      "play.http.session.algorithm" -> "HS512",
      "play.http.session.tokenPrefix" -> ""
    )
  )

  def session = JwtSession()
  def sessionCustom = JwtSession(JwtHeader(JwtAlgorithm.HS512), claimClass)
  def tokenCustom = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9." + claim64 + ".ngZsdQj8p2wvUAo8xCbJPwganGPnG5UnLkg7VrE6NgmQdV16UITjlBajZxcai_U5PjQdeN-yJtyA5kxf8O5BOQ"

  "Init FakeApplication" must {
    "have the correct config" in {
      app.configuration.getString("play.crypto.secret") mustEqual Option(secretKey)
      app.configuration.getString("play.http.session.jwtName") mustEqual Option(HEADER_NAME)
      app.configuration.getString("play.http.session.algorithm") mustEqual Option("HS512")
      app.configuration.getString("play.http.session.tokenPrefix") mustEqual Option("")
      app.configuration.getMilliseconds("play.http.session.maxAge") mustEqual Option(sessionTimeout * 1000)
    }
  }

  "JwtSession" must {
    "read default configuration" in {
      assert(JwtSession.defaultHeader === JwtHeader(JwtAlgorithm.HS512))
      assert(JwtSession.getAlgorithm === JwtAlgorithm.HS512)
    }

    "init" in {
      assert(session.headerData === Json.obj("typ" -> "JWT", "alg" -> "HS512"))
      assert(session.claimData === Json.obj("exp" -> (validTime + sessionTimeout)))
      assert(!session.isEmpty) // There is the expiration date in the claim
    }

    "serialize" in {
      assert(sessionCustom.serialize === tokenCustom)
    }

    "deserialize" in {
      assert(JwtSession.deserialize(tokenCustom) === sessionCustom)
    }
  }

  val sessionHeaderExp = Some("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJleHAiOjEzMDA4MTkzNjB9.nUA_47EPTArR_imUGiIldicJugWWjlH8miDhiwe3RcAVgCYyO7Q0LXkj504DMkRDUZKPbGKXlNxTKeKGz-xHEQ")
  val sessionHeaderUser = Some("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJleHAiOjEzMDA4MTkzNjAsInVzZXIiOnsiaWQiOjEsIm5hbWUiOiJQYXVsIn19.NfNWg47eQdH6IY-AXo_c_Zl9dMyhBev0E2XmvjLKluLf9w8kqe1Nozp4FxLB1eCEuqUuMnfqgCcq66psH5zYlw")
  val sessionHeaderExp2 = Some("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJleHAiOjEzMDA4MTkzNzF9.huJo47S37DjyAcS6POb7djzyFL0fOlk9ewaUfbEbHAnBZKpNFPvoo4U0NHrxaolH0RFd3DeN7vHQm61VBBbX5A")

  "RichResult" must {
    "access app with no user" in {
      val result = get(classicAction)
      val result2 = get(securedAction)

      status(result) mustEqual OK
      status(result2) mustEqual UNAUTHORIZED
      jwtHeader(result) mustEqual sessionHeaderExp
      jwtHeader(result2) mustEqual None
    }

    "fail to login" in {
      val result = post(loginAction, Json.obj("username" -> "whatever", "password" -> "wrong"))
      status(result) mustEqual BAD_REQUEST
      jwtHeader(result) mustEqual None
    }

    "login" in {
      val result = post(loginAction, Json.obj("username" -> "whatever", "password" -> "p4ssw0rd"))
      status(result) mustEqual OK
      jwtHeader(result) mustEqual sessionHeaderUser
    }

    "access app with user" in {
      val result = get(classicAction, sessionHeaderUser)
      val result2 = get(securedAction, sessionHeaderUser)

      status(result) mustEqual OK
      status(result2) mustEqual OK
      jwtHeader(result) mustEqual sessionHeaderUser
      jwtHeader(result2) mustEqual sessionHeaderUser
    }

    "move to the future!" in {
      jwtTime = mockTime(validTime + sessionTimeout + 1)
    }

    "timeout session" in {
      val result = get(classicAction, sessionHeaderUser)
      val result2 = get(securedAction, sessionHeaderUser)

      status(result) mustEqual OK
      status(result2) mustEqual UNAUTHORIZED
      jwtHeader(result) mustEqual sessionHeaderExp2
      jwtHeader(result2) mustEqual None
    }

    "logout" in {
      val result = get(logoutAction)
      status(result) mustEqual OK
      jwtHeader(result) mustEqual None
    }

    "access app with no user again" in {
      val result = get(classicAction)
      val result2 = get(securedAction)

      status(result) mustEqual OK
      status(result2) mustEqual UNAUTHORIZED
      jwtHeader(result) mustEqual sessionHeaderExp2
      jwtHeader(result2) mustEqual None
    }
  }
}
