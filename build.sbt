import Dependencies._
import com.typesafe.sbt.SbtGhPages.GhPagesKeys._
import com.typesafe.sbt.SbtSite.SiteKeys._
import sbt.Keys._
import sbt.Tests._
import sbt._

val previousVersion = "0.7.0"
val buildVersion = "0.7.1"

val projects = Seq("coreCommon", "playJson", "json4sNative", "json4sJackson", "circe", "play")

addCommandAlias("testAll", projects.map(p => p + "/test").mkString(";", ";", ""))

addCommandAlias("scaladoc", ";coreEdge/doc;playJsonEdge/doc;playEdge/doc;json4sNativeEdge/doc;circeEdge/doc;scaladocScript;cleanScript")

addCommandAlias("publish-doc", ";docs/makeSite;docs/ghpagesPushSite")

addCommandAlias("publishCore", ";coreCommonEdge/publishSigned")
addCommandAlias("publishPlayJson", ";playJsonEdge/publishSigned")
addCommandAlias("publishJson4Native", ";json4sNativeEdge/publishSigned")
addCommandAlias("publishJson4Jackson", ";json4sJacksonEdge/publishSigned")
addCommandAlias("publishCirce", ";circeEdge/publishSigned")
addCommandAlias("publishPlay", ";playEdge/publishSigned")

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

lazy val jwtScala = project.in(file("."))
  .settings(localSettings)
  .settings(
    name := "jwt-scala"
  )
  .aggregate(play, json4sNative, json4sJackson, circe)
  .dependsOn(play, json4sNative, json4sJackson, circe)

lazy val docs = project.in(file("docs"))
  .settings(name := "jwt-docs")
  .settings(localSettings)
  .settings(site.settings)
  .settings(ghpages.settings)
  .settings(tutSettings)
  .settings(docSettings)
  .settings(
    libraryDependencies ++= Seq(Libs.playJson, Libs.play, Libs.playTestProvided, Libs.json4sNative, Libs.circeCore, Libs.circeGeneric, Libs.circeParse)
  )
  .dependsOn(play, json4sNative, circe)


lazy val core = project.in(file("core"))
  .settings(releaseSettings)
  .settings(
    name := "jwt-core",
    libraryDependencies ++= Seq(Libs.bouncyCastle)
  )

lazy val jsonCommon = project.in(file("json/common"))
  .settings(releaseSettings)
  .settings(
    name := "jwt-json-common"
  )
  .aggregate(core)
  .dependsOn(core % "compile->compile;test->test")

lazy val circe = project.in(file("json/circe"))
  .settings(releaseSettings)
  .settings(
    name := "jwt-circe",
    libraryDependencies ++= Seq(Libs.circeCore, Libs.circeGeneric, Libs.circeParse)
  )
  .aggregate(jsonCommon)
  .dependsOn(jsonCommon % "compile->compile;test->test")


lazy val json4sCommon = project.in(file("json/json4s-common"))
  .settings(releaseSettings)
  .settings(
    name := "jwt-json4s-common",
    libraryDependencies ++= Seq(Libs.json4sCore)
  )
  .aggregate(jsonCommon)
  .dependsOn(jsonCommon % "compile->compile;test->test")


lazy val json4sNative = project.in(file("json/json4s-native"))
  .settings(releaseSettings)
  .settings(
    name := "jwt-json4s-native",
    libraryDependencies ++= Seq(Libs.json4sNative)
  )
  .aggregate(json4sCommon)
  .dependsOn(json4sCommon % "compile->compile;test->test")


lazy val json4sJackson = project.in(file("json/json4s-jackson"))
  .settings(releaseSettings)
  .settings(
    name := "jwt-json4s-jackson",
    libraryDependencies ++= Seq(Libs.json4sJackson)
  )
  .aggregate(json4sCommon)
  .dependsOn(json4sCommon % "compile->compile;test->test")


lazy val playJson = project.in(file("json/play-json"))
  .settings(releaseSettings)
  .settings(
    name := "jwt-play-json",
    libraryDependencies ++= Seq(
      Libs.playJson
    )
  )
  .aggregate(jsonCommon)
  .dependsOn(jsonCommon % "compile->compile;test->test")


def groupPlayTest(tests: Seq[TestDefinition]) = tests.map { t =>
  new Group(t.name, Seq(t), SubProcess(javaOptions = Seq.empty[String]))
}

lazy val play = project.in(file("play"))
  .settings(releaseSettings)
  .settings(
    name := "jwt-play",
    libraryDependencies ++= Seq(
      Libs.play,
      Libs.playTest,
      Libs.scalatestPlus
    ),
    testGrouping in Test <<= definedTests in Test map groupPlayTest
  )
  .aggregate(playJson)
  .dependsOn(playJson % "compile->compile;test->test")

lazy val examplePlayAngularProject = project.in(file("examples/play-angular"))
  .settings(localSettings)
  .settings(
    name := "playAngular",
    routesGenerator := InjectedRoutesGenerator
  )
  .enablePlugins(PlayScala)
  .aggregate(play)
  .dependsOn(play)
