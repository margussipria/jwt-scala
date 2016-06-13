package controllers

import _root_.play.api.mvc.{Result, Results}
import _root_.play.api.test.Helpers._
import _root_.play.api.test.{FakeApplication, FakeRequest}
import org.scalatestplus.play.{OneAppPerSuite, PlaySpec}
import play.api.libs.json.Json

import scala.concurrent.Future

class ApplicationHmacSpec extends PlaySpec with OneAppPerSuite with Results {

  implicit override lazy val app: play.api.Application = FakeApplication()

  val Header = "Authorization"

  "Application" should {
    val controller = new Application

    "return correct status for guest user" in {
      val indexResult: Future[Result] = controller.index().apply(FakeRequest())
      status(indexResult) must equal (OK)
      header(Header, indexResult) must be(empty)

      val loginResult: Future[Result] = controller.login().apply(FakeRequest().withBody(
        Json.obj()
      ))
      status(loginResult) must equal (BAD_REQUEST)
      header(Header, loginResult) must be(empty)

      val publicApiResult: Future[Result] = controller.publicApi().apply(FakeRequest())
      status(publicApiResult) must equal (OK)
      header(Header, publicApiResult) must be(empty)

      val privateApiResult: Future[Result] = controller.privateApi().apply(FakeRequest())
      status(privateApiResult) must equal (UNAUTHORIZED)
      header(Header, privateApiResult) must be(empty)

      val adminApiResult: Future[Result] = controller.adminApi().apply(FakeRequest())
      status(adminApiResult) must equal (UNAUTHORIZED)
      header(Header, adminApiResult) must be(empty)
    }

    "login user named pepper correctly" in {
      val indexResult: Future[Result] = controller.index().apply(FakeRequest())
      status(indexResult) must equal(OK)
      header(Header, indexResult) must be(empty)

      val loginResult: Future[Result] = controller.login().apply(FakeRequest().withBody(
        Json.obj("username" -> "pepper", "password" -> "red")
      ))
      status(loginResult) must equal(OK)
      header(Header, loginResult) must be(defined)
      val authorization: String = header(Header, loginResult).get

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

    "login admin correctly" in {
      val indexResult: Future[Result] = controller.index().apply(FakeRequest())
      status(indexResult) must equal(OK)
      header(Header, indexResult) must be(empty)

      val loginResult: Future[Result] = controller.login().apply(FakeRequest().withBody(
        Json.obj("username" -> "admin", "password" -> "red")
      ))
      status(loginResult) must equal(OK)
      header(Header, loginResult) must be(defined)
      val authorization: String = header(Header, loginResult).get

      val authenticatedRequest = FakeRequest().withHeaders(Header -> authorization)

      val publicApiResult: Future[Result] = controller.publicApi().apply(authenticatedRequest)
      status(publicApiResult) must equal(OK)
      header(Header, publicApiResult) must be(empty)

      val privateApiResult: Future[Result] = controller.privateApi().apply(authenticatedRequest)
      status(privateApiResult) must equal(OK)
      header(Header, privateApiResult) must be(defined)

      val adminApiResult: Future[Result] = controller.adminApi().apply(authenticatedRequest)
      status(adminApiResult) must equal(OK)
      header(Header, adminApiResult) must be(defined)
    }
  }
}
