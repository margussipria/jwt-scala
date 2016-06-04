package eu.sipria.jwt

import akka.stream.Materializer
import eu.sipria.jwt.algorithms.JwtAlgorithm
import org.scalatestplus.play._
import play.api.Application
import play.api.libs.json._
import play.api.test.Helpers._
import play.api.test._

class JwtSessionSpec extends PlaySpec with OneAppPerSuite with PlayFixture {
  val materializer: Materializer = app.materializer

  implicit val jwtTime = new JwtTime

  def HEADER_NAME = "Authorization"

  implicit override lazy val app: Application = FakeApplication(
    additionalConfiguration = Map("play.crypto.secret" -> secretKey)
  )

  val session = JwtSession().withHeader(JwtHeader(JwtAlgorithm.HmacSHA256))
  val session2 = session ++ (("a", 1), ("b", "c"), ("e", true), ("f", Seq(1, 2, 3)), ("user", user))
  val session3 = JwtSession(JwtHeader(JwtAlgorithm.HmacSHA256), claimClass)
  // This is session3 serialized (if no bug...)
  val token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIbWFjU0hBMjU2In0." + claim64 + ".-3BM6yrNy3a8E2QtEYszKes2Rij80sfpgBAmzrJeJuk"

  "Init FakeApplication" must {
    "have the correct config" in {
      app.configuration.getString("play.crypto.secret") mustEqual Option(secretKey)
    }
  }

  "JwtSession" must {
    "read default configuration" in {
      assert(JwtSession.defaultHeader == JwtHeader(JwtAlgorithm.HmacSHA256))
    }

    "init" in {
      assert(session.headerData == Json.obj("typ" -> "JWT", "alg" -> "HmacSHA256"))
      assert(session.claimData == Json.obj())
      assert(session.isEmpty)
    }

    "add stuff" in {
      assert((session + Json.obj("a" -> 1)).claimData == Json.obj("a" -> 1))
      assert((session + ("a", 1) + ("b", "c")).claimData == Json.obj("a" -> 1, "b" -> "c"))
      assert((session + ("user", user)).claimData == Json.obj("user" -> userJson))
      assert((session ++ (("a", 1), ("b", "c"))).claimData == Json.obj("a" -> 1, "b" -> "c"))

      assert((session + ("a", 1) + ("b", "c") + ("user", user)).claimData == Json.obj("a" -> 1, "b" -> "c", "user" -> userJson))

      val sessionBis = session + ("a", 1) + ("b", "c")
      val sessionTer = sessionBis ++ (("d", true), ("e", 42))
      val sessionQuad = sessionTer + ("user", user)
      assert(sessionQuad.claimData == Json.obj("a" -> 1, "b" -> "c", "d" -> true, "e" -> 42, "user" -> userJson))
    }

    "remove stuff" in {
      assert((session2 - "e" - "f" - "user").claimData == Json.obj("a" -> 1, "b" -> "c"))
      assert((session2 -- ("e", "f", "user")).claimData == Json.obj("a" -> 1, "b" -> "c"))
    }

    "get stuff" in {
      assert(session2("a") == Option(JsNumber(1)))
      assert(session2("b") == Option(JsString("c")))
      assert(session2("e") == Option(JsBoolean(true)))
      assert(session2("f") == Option(Json.arr(1, 2, 3)))
      assert(session2("nope") match { case None => true; case _ => false })
      assert(session2.get("a") == Option(JsNumber(1)))
      assert(session2.get("b") == Option(JsString("c")))
      assert(session2.get("e") == Option(JsBoolean(true)))
      assert(session2.get("f") == Option(Json.arr(1, 2, 3)))
      assert(session2.get("nope") match { case None => true; case _ => false })
      assert(session2.getAs[User]("user") === Option(user))
      assert(session2.getAs[User]("nope") === None)
    }

    "test emptiness" in {
      assert(session.isEmpty)
      assert(!session2.isEmpty)
    }

    "serialize" in {
      assert(session3.serialize == token)
    }

    "deserialize" in {
      implicit val jwtTime = mockValidTime
      assert(JwtSession.deserialize(token) == session3)
    }
  }

  val sessionHeader = Some("Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIbWFjU0hBMjU2In0.eyJ1c2VyIjp7ImlkIjoxLCJuYW1lIjoiUGF1bCJ9fQ.McCC-wVflYAnnk6yRoojeNszDfayCsK9C6NVoMFMq24")

  "RichResult" must {
    "access app with no user" in {
      val result = get(classicAction)
      val result2 = get(securedAction)

      status(result) mustEqual OK
      status(result2) mustEqual UNAUTHORIZED
      jwtHeader(result) mustEqual None
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
      jwtHeader(result) mustEqual sessionHeader
    }

    "access app with user" in {
      val result = get(classicAction, sessionHeader)
      val result2 = get(securedAction, sessionHeader)

      status(result) mustEqual OK
      status(result2) mustEqual OK
      // Wuuut? Why None? Because since there is no "session.maxAge", we don't need to refresh the token
      // it's up to the client-side code to save it as long as it needs it
      jwtHeader(result) mustEqual None
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
      jwtHeader(result) mustEqual None
      jwtHeader(result2) mustEqual None
    }
  }
}
