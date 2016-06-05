package eu.sipria.play.jwt

import akka.stream.Materializer
import akka.util.Timeout
import eu.sipria.jwt.play.JwtPlayJson
import eu.sipria.jwt.{Fixture, JwtClaim, JwtTime}
import play.api.Application
import play.api.libs.json._
import play.api.mvc.Results._
import play.api.mvc._
import play.api.test.Helpers._
import play.api.test._

import scala.concurrent.Future

case class User(id: Long, name: String)

trait PlayFixture extends Fixture {
  def HEADER_NAME: String
  def materializer: Materializer

  implicit val userFormat = Json.format[User]

  implicit def jwtTime: JwtTime
  implicit def app: Application

  def claimClass: JwtClaim[JsObject] = claimClassString.copy(content = JwtPlayJson.parse(claimClassString.content))

  val user = User(1, "Paul")
  val userJson = Json.obj("id" -> 1, "name" -> "Paul")

  val loginAction: EssentialAction = Action { implicit request =>
    val username = (request.body.asJson.get \ "username").as[String]
    val password = (request.body.asJson.get \ "password").as[String]

    password match {
      case "p4ssw0rd" => Ok.addingToJwtSession("user", user)
      case _ => BadRequest
    }
  }

  val logoutAction: EssentialAction = Action {
    Ok.withoutJwtSession
  }

  val classicAction: EssentialAction = Action { implicit request =>
    Ok.refreshJwtSession
  }

  val securedAction: EssentialAction = Action { implicit request =>
    request.jwtSession.getAs[User]("user") match {
      case Some(u) => Ok.refreshJwtSession
      case _ => Unauthorized.withoutJwtSession
    }
  }

  def get(action: EssentialAction, header: Option[String] = None) = {
    implicit val mat: Materializer = materializer
    val request = header match {
      case Some(h) => FakeRequest(GET, "/something").withHeaders((JwtSession.getHeaderName, h))
      case _ => FakeRequest(GET, "/something")
    }

    call(action, request)
  }

  def post(action: EssentialAction, body: JsObject) = {
    implicit val mat: Materializer = materializer
    call(action, FakeRequest(POST, "/something").withJsonBody(body))
  }

  def jwtHeader(of: Future[Result])(implicit timeout: Timeout): Option[String] = header(JwtSession.getHeaderName, of)(timeout)
}
