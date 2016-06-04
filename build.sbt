import Dependencies._
import com.typesafe.sbt.SbtGhPages.GhPagesKeys._
import com.typesafe.sbt.SbtSite.SiteKeys._
import sbt.Keys._
import sbt.Tests._
import sbt._

val previousVersion = "0.7.0"
val buildVersion = "0.7.1"

val baseSettings = Seq(
  organization := "com.pauldijou",
  version := buildVersion,
  scalaVersion := "2.11.8",
  //crossScalaVersions := Seq("2.10.6", "2.11.8"),
  //crossVersion := CrossVersion.binary,
  autoAPIMappings := true,
  resolvers ++= Seq(
    "Typesafe repository releases" at "http://repo.typesafe.com/typesafe/releases/"
  ),
  libraryDependencies ++= Seq(Libs.scalatest),
  scalacOptions in (Compile, doc) ++= Seq("-unchecked", "-deprecation"),
  //aggregate in test := false,
  fork in test := true,
  parallelExecution in test := false
)

// Normal published settings
val releaseSettings = baseSettings //++ publishSettings

// Local non-published projects
val localSettings = baseSettings //++ noPublishSettings


val docSettings = Seq(
  site.addMappingsToSiteDir(tut, "_includes/tut"),
  ghpagesNoJekyll := false,
  siteMappings ++= Seq(
    file("README.md") -> "_includes/README.md"
  ),
  git.remoteRepo := "git@github.com:pauldijou/jwt-scala.git",
  includeFilter in makeSite := "*.html" | "*.css" | "*.png" | "*.jpg" | "*.gif" | "*.js" | "*.swf" | "*.yml" | "*.md" | "*.scss"
)

lazy val jwtScala = Project("jwt-scala", file("."))
  .settings(localSettings)
  .aggregate(play, json4sNative, json4sJackson, circe)
  .dependsOn(play, json4sNative, json4sJackson, circe)


lazy val docs = Project("jwt-docs", file("docs"))
  .settings(
    localSettings,
    site.settings,
    ghpages.settings,
    tutSettings,
    docSettings,
    libraryDependencies ++= Seq(Libs.playJson, Libs.play, Libs.playTestProvided, Libs.json4sNative, Libs.circeCore, Libs.circeGeneric, Libs.circeParse)
  )
  .dependsOn(play)


def module(name: String, dir: String): Project = Project(name, file(dir))
  .settings(releaseSettings)


lazy val core = module("jwt-core", "core")
  .settings(
    libraryDependencies ++= Seq(Libs.bouncyCastle)
  )


lazy val circe = module("jwt-circe", "json/circe")
  .settings(
    libraryDependencies ++= Seq(Libs.circeCore, Libs.circeGeneric, Libs.circeParse)
  )
  .aggregate(core)
  .dependsOn(core % "compile->compile;test->test")


lazy val json4sCommon = module("jwt-json4s-common", "json/json4s-common")
  .settings(
    libraryDependencies ++= Seq(Libs.json4sCore)
  )
  .aggregate(core)
  .dependsOn(core % "compile->compile;test->test")


lazy val json4sNative = module("jwt-json4s-native", "json/json4s-native")
  .settings(
    libraryDependencies ++= Seq(Libs.json4sNative)
  )
  .aggregate(json4sCommon)
  .dependsOn(json4sCommon % "compile->compile;test->test")


lazy val json4sJackson = module("jwt-json4s-jackson", "json/json4s-jackson")
  .settings(
    libraryDependencies ++= Seq(Libs.json4sJackson)
  )
  .aggregate(json4sCommon)
  .dependsOn(json4sCommon % "compile->compile;test->test")


lazy val playJson = module("jwt-play-json", "json/play-json")
  .settings(
    libraryDependencies ++= Seq(
      Libs.playJson
    )
  )
  .aggregate(core)
  .dependsOn(core % "compile->compile;test->test")


def groupPlayTest(tests: Seq[TestDefinition]) = tests.map { t =>
  new Group(t.name, Seq(t), SubProcess(javaOptions = Seq.empty[String]))
}

lazy val play = module("jwt-play", "play")
  .settings(
    libraryDependencies ++= Seq(
      Libs.play,
      Libs.playTest,
      Libs.scalatestPlus
    ),
    testGrouping in Test <<= definedTests in Test map groupPlayTest
  )
  .aggregate(playJson)
  .dependsOn(playJson % "compile->compile;test->test")


lazy val examplePlayAngularProject = module("play-angular-example", "examples/play-angular")
  .settings(localSettings)
  .settings(
    routesGenerator := InjectedRoutesGenerator
  )
  .enablePlugins(PlayScala)
  .aggregate(play)
  .dependsOn(play)
