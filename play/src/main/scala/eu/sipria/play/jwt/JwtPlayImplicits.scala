package eu.sipria.play.jwt

import eu.sipria.jwt.JwtTime
import play.api.Application
import play.api.libs.json.Json.JsValueWrapper
import play.api.libs.json.{JsObject, JsString, Writes}
import play.api.mvc.{RequestHeader, Result}

trait JwtPlayImplicits {
  private def sanitizeHeader(header: String)(implicit app: Application): String = {
    if (header.startsWith(JwtSession.getTokenPrefix)) {
      header.substring(JwtSession.getTokenPrefix.length()).trim
    } else {
      header.trim
    }
  }

  private def requestToJwtSession(request: RequestHeader)(implicit jwtTime: JwtTime, app: Application): JwtSession = {
    request.headers.get(JwtSession.getHeaderName).map(sanitizeHeader).map(JwtSession.deserialize).getOrElse(JwtSession())
  }

  /** By adding `import eu.sipria.play.jwt._`, you will implicitly add all those methods to `Result` allowing you to easily manipulate
    * the [[JwtSession]] inside your Play application.
    *
    * {{{
    * package controllers
    *
    * import play.api._
    * import play.api.mvc._
    * import eu.sipria.play.jwt._
    *
    * object Application extends Controller {
    *   def login = Action { implicit request =>
    *     Ok.addingToJwtSession(("logged", true))
    *   }
    *
    *   def logout = Action { implicit request =>
    *     Ok.withoutJwtSession
    *   }
    * }
    * }}}
    */
  implicit class RichResult(result: Result) {
    /** Retrieve the current [[JwtSession]] from the headers (first from the Result then from the RequestHeader), if none, create a new one.
      *
      * @return the JwtSession inside the headers or a new one
      */
    def jwtSession(implicit request: RequestHeader, jwtTime: JwtTime, app: Application): JwtSession = {
      result.header.headers.get(JwtSession.getHeaderName) match {
        case Some(token) => JwtSession.deserialize(sanitizeHeader(token))
        case None => requestToJwtSession(request)
      }
    }

    /** If the Play app has a session.maxAge config, it will extend the expiration of the [[JwtSession]] by that time, if not, it will do nothing.
      *
      * @return the same Result with, eventually, a prolonged [[JwtSession]]
      */
    def refreshJwtSession(implicit request: RequestHeader, jwtTime: JwtTime, app: Application): Result = JwtSession.getMaxAge match {
      case None => result
      case _ => result.withJwtSession(jwtSession.refresh)
    }

    /** Override the current [[JwtSession]] with a new one */
    def withJwtSession(session: JwtSession)(implicit app: Application): Result = {
      val tokenPrefix = if (JwtSession.getTokenPrefix.nonEmpty) { JwtSession.getTokenPrefix +  " "  } else { "" }
      result.withHeaders(JwtSession.getHeaderName -> (tokenPrefix + session.serialize))
    }

    /** Override the current [[JwtSession]] with a new one created from a JsObject */
    def withJwtSession(session: JsObject)(implicit app: Application): Result = {
      withJwtSession(JwtSession(session))
    }

    /** Override the current [[JwtSession]] with a new one created from a sequence of tuples */
    def withJwtSession(fields: (String, JsValueWrapper)*)(implicit jwtTime: JwtTime, app: Application): Result = {
      withJwtSession(JwtSession(fields: _*))
    }

    /** Override the current [[JwtSession]] with a new empty one */
    def withNewJwtSession(implicit jwtTime: JwtTime, app: Application): Result = {
      withJwtSession(JwtSession())
    }

    /** Remove the current [[JwtSession]], which means removing the associated HTTP header */
    def withoutJwtSession(implicit app: Application): Result = {
      result.copy(header = result.header.copy(headers = result.header.headers - JwtSession.getHeaderName))
    }

    /** Keep the current [[JwtSession]] and add some values in it, if a key is already defined, it will be overridden. */
    def addingToJwtSession(values: (String, String)*)(implicit request: RequestHeader, jwtTime: JwtTime, app: Application): Result = {
      withJwtSession(jwtSession + new JsObject(values.map(kv => kv._1 -> JsString(kv._2)).toMap))
    }

    /** Keep the current [[JwtSession]] and add some values in it, if a key is already defined, it will be overridden. */
    def addingToJwtSession[A: Writes](key: String, value: A)(implicit request: RequestHeader, jwtTime: JwtTime, app: Application): Result = {
      withJwtSession(jwtSession + (key, value))
    }

    /** Remove some keys from the current [[JwtSession]] */
    def removingFromJwtSession(keys: String*)(implicit request: RequestHeader, jwtTime: JwtTime, app: Application): Result = {
      withJwtSession(jwtSession -- (keys: _*))
    }
  }

  /** By adding `import eu.sipria.play.jwt._`, you will implicitly add this method to `RequestHeader` allowing you to easily retrieve
    * the [[JwtSession]] inside your Play application.
    *
    * {{{
    * package controllers
    *
    * import play.api._
    * import play.api.mvc._
    * import eu.sipria.play.jwt._
    *
    * object Application extends Controller {
    *   def index = Action { request =>
    *     val session: JwtSession = request.jwtSession
    *   }
    * }
    * }}}
    */
  implicit class RichRequestHeader(request: RequestHeader) {
    /** Return the current [[JwtSession]] from the request */
    def jwtSession(implicit jwtTime: JwtTime, app: Application): JwtSession = requestToJwtSession(request)
  }
}
