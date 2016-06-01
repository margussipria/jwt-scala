import Dependencies._
import com.typesafe.sbt.SbtGhPages.GhPagesKeys._
import com.typesafe.sbt.SbtSite.SiteKeys._
import sbt.Keys._
import sbt.Tests._
import sbt._

val previousVersion = "0.7.0"
val buildVersion = "0.7.1"

val projects = Seq("jwt-core", "jwt-json-common", "jwt-play-json", "jwt-json4s-native", "jwt-json4s-jackson", "jwt-circe", "jwt-play")

addCommandAlias("testAll", ";" + projects.map(p => p + "/test").mkString(";"))

addCommandAlias("scaladoc", ";" + projects.map(p => p + "/doc").mkString(";") + ";scaladocScript;cleanScript")

addCommandAlias("publish-doc", ";docs/makeSite;docs/ghpagesPushSite")

addCommandAlias("publishCore", ";jwt-core/publishSigned")
addCommandAlias("publishPlayJson", ";jwt-play-json/publishSigned")
addCommandAlias("publishJson4Native", ";jwt-json4s-native/publishSigned")
addCommandAlias("publishJson4Jackson", ";jwt-json4s-jackson/publishSigned")
addCommandAlias("publishCirce", ";jwt-circe/publishSigned")
addCommandAlias("publishPlay", ";jwt-play/publishSigned")

// Do not cross-build for Play project since Scala 2.10 support was dropped
addCommandAlias("publishAll", ";publishPlayJson;+publishJson4Native;+publishJson4Jackson;+publishCirce;publishPlay")

addCommandAlias("release", ";bumpScript;scaladoc;publish-doc;publishAll;sonatypeRelease;pushScript")

lazy val scaladocScript = taskKey[Unit]("Generate scaladoc and copy it to docs site")
scaladocScript := {
  "./scripts/scaladoc.sh " + buildVersion !
}

lazy val bumpScript = taskKey[Unit]("Bump the new version all around")
bumpScript := {
  "./scripts/bump.sh "+previousVersion+" "+buildVersion !
}

lazy val pushScript = taskKey[Unit]("Push to GitHub")
pushScript := {
  "./scripts/pu.sh "+buildVersion !
}

lazy val cleanScript = taskKey[Unit]("Clean tmp files")
cleanScript := {
  "./scripts/clean.sh" !
}

val baseSettings = Seq(
  organization := "com.pauldijou",
  version := buildVersion,
  scalaVersion := "2.11.8",
  crossScalaVersions := Seq("2.10.6", "2.11.8"),
  crossVersion := CrossVersion.binary,
  autoAPIMappings := true,
  resolvers ++= Seq(
    "Typesafe repository releases" at "http://repo.typesafe.com/typesafe/releases/"
  ),
  libraryDependencies ++= Seq(Libs.scalatest, Libs.jmockit),
  scalacOptions in (Compile, doc) ++= Seq("-unchecked", "-deprecation"),
  aggregate in test := false,
  fork in test := true,
  parallelExecution in test := false
)

val publishSettings = Seq(
  homepage := Some(url("http://pauldijou.fr/jwt-scala/")),
  organizationHomepage := Some(url("http://pauldijou.github.io/")),
  apiURL := Some(url("http://pauldijou.fr/jwt-scala/api/")),
  publishMavenStyle := true,
  publishArtifact in Test := false,
  licenses += ("Apache-2.0", url("http://www.apache.org/licenses/LICENSE-2.0")),
  publishTo := {
    val nexus = "https://oss.sonatype.org/"
    if (isSnapshot.value)
      Some("snapshots" at nexus + "content/repositories/snapshots")
    else
      Some("releases"  at nexus + "service/local/staging/deploy/maven2")
  },
  pomIncludeRepository := { _ => false },
  pomExtra := (
    <scm>
      <url>git@github.com:pauldijou/jwt-scala.git</url>
      <connection>scm:git:git@github.com:pauldijou/jwt-scala.git</connection>
    </scm>
    <developers>
      <developer>
        <id>pdi</id>
        <name>Paul Dijou</name>
        <url>http://pauldijou.fr</url>
      </developer>
    </developers>)
)

val noPublishSettings = Seq(
  publish := (),
  publishLocal := (),
  publishArtifact := false
)

// Normal published settings
val releaseSettings = baseSettings ++ publishSettings

// Local non-published projects
val localSettings = baseSettings ++ noPublishSettings


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
  .dependsOn(play, json4sNative, circe)


def module(name: String, dir: String): Project = Project(name, file(dir))
  .settings(releaseSettings)


lazy val core = module("jwt-core", "core")
  .settings(
    libraryDependencies ++= Seq(Libs.bouncyCastle)
  )


lazy val jsonCommon = module("jwt-json-common", "json/common")
  .aggregate(core)
  .dependsOn(core % "compile->compile;test->test")


lazy val circe = module("jwt-circe", "json/circe")
  .settings(
    libraryDependencies ++= Seq(Libs.circeCore, Libs.circeGeneric, Libs.circeParse)
  )
  .aggregate(jsonCommon)
  .dependsOn(jsonCommon % "compile->compile;test->test")


lazy val json4sCommon = module("jwt-json4s-common", "json/json4s-common")
  .settings(
    libraryDependencies ++= Seq(Libs.json4sCore)
  )
  .aggregate(jsonCommon)
  .dependsOn(jsonCommon % "compile->compile;test->test")


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
  .aggregate(jsonCommon)
  .dependsOn(jsonCommon % "compile->compile;test->test")


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
