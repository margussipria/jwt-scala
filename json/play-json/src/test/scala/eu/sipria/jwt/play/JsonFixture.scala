package eu.sipria.jwt.play

import eu.sipria.jwt.algorithms.JwtAlgorithm
import eu.sipria.jwt.{DataEntryBase, JsonCommonFixture, JsonDataEntryTrait, JwtHeader}
import play.api.libs.json.JsObject

case class JsonDataEntry(
  alg: JwtAlgorithm,
  header: String,
  headerClass: JwtHeader,
  header64: String,
  signature: String,
  token: String,
  tokenUnsigned: String,
  tokenEmpty: String,
  headerJson: JsObject
) extends JsonDataEntryTrait[JsObject]

trait JsonFixture extends JsonCommonFixture[JsObject] {
  lazy val claimJson = jwtClaimWriter.writes(claimClass).as[JsObject]
  lazy val headerEmptyJson = jwtHeaderWriter.writes(headerClassEmpty).as[JsObject]

  def mapData(data: DataEntryBase): JsonDataEntry = JsonDataEntry(
    alg = data.alg,
    header = data.header,
    headerClass = data.headerClass,
    header64 = data.header64,
    signature = data.signature,
    token = data.token,
    tokenUnsigned = data.tokenUnsigned,
    tokenEmpty = data.tokenEmpty,
    headerJson = jwtHeaderWriter.writes(data.headerClass).as[JsObject]
  )
}
