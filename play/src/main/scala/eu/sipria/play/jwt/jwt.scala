package eu.sipria.play

import eu.sipria.jwt.play.{JwtJsonImplicits, JwtPlayJson}

package object jwt extends JwtPlayImplicits with JwtJsonImplicits {
  implicit val jwtJson = JwtPlayJson
}
