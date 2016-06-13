package controllers

import eu.sipria.jwt.JwtTime
import eu.sipria.play.jwt._
import models.User
import play.api.mvc.Results._
import play.api.mvc._

import scala.concurrent.Future
import scala.util.Try

class AuthenticatedRequest[A](val user: User, request: Request[A]) extends WrappedRequest[A](request)

trait Secured {
  implicit def app: play.api.Application

  val Authenticated = new AuthenticatedAction
  val Admin = new AdminAction
}

class AuthenticatedAction(implicit jwtTime: JwtTime, app: play.api.Application) extends ActionBuilder[AuthenticatedRequest] {
  def invokeBlock[A](request: Request[A], block: AuthenticatedRequest[A] => Future[Result]) = {
    Try {
      request.jwtSession.getAs[User]("user") match {
        case Some(user) => block(new AuthenticatedRequest(user, request)).map(_.refreshJwtSession(request, jwtTime, app))(executionContext)
        case _ => Future.successful(Unauthorized)
      }
    } getOrElse {
      Future.successful(Unauthorized)
    }
  }
}

class AdminAction(implicit jwtTime: JwtTime, app: play.api.Application) extends ActionBuilder[AuthenticatedRequest] {
  private lazy val action = new AuthenticatedAction

  def invokeBlock[A](request: Request[A], block: AuthenticatedRequest[A] => Future[Result]) = {
    action.invokeBlock(request, { request: AuthenticatedRequest[A] =>
      request.user match {
        case user if user.isAdmin => block(new AuthenticatedRequest(user, request))
        case user => Future.successful(Forbidden.refreshJwtSession(request, jwtTime, app))
      }
    })
  }
}
