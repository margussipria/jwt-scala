package eu.sipria.play.jwt

import akka.stream.Materializer
import eu.sipria.jwt.algorithms.JwtAlgorithm
import eu.sipria.jwt.{JwtHeader, JwtTime}
import org.scalatestplus.play._
import play.api.Application
import play.api.libs.json._
import play.api.mvc._
import play.api.test._

class JwtResultSpec extends PlaySpec with OneAppPerSuite with PlayFixture {
  val HEADER_NAME = "Authorization"
  val materializer: Materializer = app.materializer

  implicit val jwtTime = new JwtTime

  implicit override lazy val app: Application = FakeApplication(
    additionalConfiguration = Map("play.crypto.secret" -> secretKey)
  )

  val session = JwtSession().withHeader(JwtHeader(JwtAlgorithm.HmacSHA256))

  "JwtResult" must {
    "support basic scenario" in {
      implicit val request = FakeRequest().withHeaders(("Authorization", "Bearer " + session.serialize))
      var result: Result = Results.Ok

      // We can already get a JwtSession from our implicit RequestHeader
      assert(result.jwtSession.claimData === Json.obj())

      // Setting a new empty JwtSession
      result = result.withNewJwtSession
      assert(result.jwtSession.claimData === Json.obj())

      // Or from an existing JwtSession
      result = result.withJwtSession(session)
      assert(result.jwtSession.claimData === Json.obj())

      // Or from a JsObject
      result = result.withJwtSession(Json.obj(("id", 1), ("key", "value")))
      assert(result.jwtSession.claimData === Json.obj("id" -> 1, "key" -> "value"))

      // Or from (key, value)
      result = result.withJwtSession(("id", 1), ("key", "value"))
      assert(result.jwtSession.claimData === Json.obj("id" -> 1, "key" -> "value"))

      // We can add stuff to the current session (only (String, String))
      result = result.addingToJwtSession(("key2", "value2"), ("key3", "value3"))
      assert(result.jwtSession.claimData === Json.obj("id" -> 1, "key" -> "value", "key2" -> "value2", "key3" -> "value3"))

      // Or directly classes or objects if you have the correct implicit Writes
      result = result.addingToJwtSession("user", User(1, "Paul"))
      assert(result.jwtSession.claimData === Json.obj("id" -> 1, "key" -> "value", "key2" -> "value2", "key3" -> "value3", "user" -> Json.obj("id" -> 1, "name" -> "Paul")))

      // Removing from session
      result = result.removingFromJwtSession("key2", "key3")
      assert(result.jwtSession.claimData === Json.obj("id" -> 1, "key" -> "value", "user" -> Json.obj("id" -> 1, "name" -> "Paul")))

      // Refresh the current session
      result = result.refreshJwtSession
      assert(result.jwtSession.claimData === Json.obj("id" -> 1, "key" -> "value", "user" -> Json.obj("id" -> 1, "name" -> "Paul")))

      // So, at the end, you can do
      assert(result.jwtSession.getAs[User]("user") === Some(User(1, "Paul")))
    }
  }
}
