package com.slickqa.slicker

import com.slickqa.slicker.auth.ProjectPermissionSeparator
import com.slickqa.slicker.auth.SlickJWTAuthImpl
import io.vertx.core.AbstractVerticle
import io.vertx.core.Future
import io.vertx.core.http.HttpClientOptions
import io.vertx.core.json.JsonObject
import io.vertx.core.logging.Logger
import io.vertx.core.logging.LoggerFactory
import io.vertx.ext.web.Router
import io.vertx.ext.web.handler.JWTAuthHandler
import java.net.URL
import org.litote.kmongo.async.*

/**
 * Created by jason.corbett on 1/9/17.
 */
@Suppress("unused")
class SlickerVerticle : AbstractVerticle() {
    val log: Logger = LoggerFactory.getLogger(SlickerVerticle::class.java)
    val CONFIG_KEY_KEYCLOAK_URL = "keycloak-url"
    val CONFIG_KEY_KEYCLOAK_REALM = "keycloak-realm"
    val requiredOptions = arrayOf(CONFIG_KEY_KEYCLOAK_URL, CONFIG_KEY_KEYCLOAK_REALM)

    override fun start(startFuture: Future<Void>?) {
        log.debug("Getting deployment config")
        val deploymentConfig = vertx.getOrCreateContext().config()

        val missingOptions = requiredOptions.filterNot { deploymentConfig.containsKey(it) }
        if(missingOptions.isNotEmpty()) {
            startFuture?.fail("Missing deployment config entries for: ${missingOptions.joinToString()}")
            return
        }

        val router = Router.router(vertx)

        val keycloakUrl = URL(deploymentConfig.getString(CONFIG_KEY_KEYCLOAK_URL))

        val httpClient = vertx.createHttpClient(HttpClientOptions()
                                                .setDefaultHost(keycloakUrl.host)
                                                .setDefaultPort(keycloakUrl.port)
                                                .setSsl(keycloakUrl.protocol == "https"))

        val log = LoggerFactory.getLogger("slicker")

        val requestUrl = arrayOf(keycloakUrl.path, "realms", deploymentConfig.getString(CONFIG_KEY_KEYCLOAK_REALM)).joinToString("/","", "/")
        httpClient.getNow(requestUrl, fun(httpResponse) {
            if(httpResponse.statusCode() == 200) {
                httpResponse.bodyHandler({
                    val realmConfig = JsonObject(it.toString())
                    val JwtConfig = json(
                            "public-key" to realmConfig.getString("public_key"),
                            "permissionsClaimKey" to "realm_access/roles"
                    )
                    val jwtAuth = SlickJWTAuthImpl(vertx, JwtConfig)
                    router.route("/api/*").handler(JWTAuthHandler.create(jwtAuth))
                    router.route("/api/*").handler({
                        val user = it.user()
                        if(user != null) {
                            log.info("User ${user.principal().getString("preferred_username")} made request to ${it.normalisedPath()}")
                        }
                        it.next()
                    })

                    router.route("/api/authCheck/:project/:permission").handler({
                        val user = it.user()
                        val permission = it.request().params().get("project") + ProjectPermissionSeparator +
                                         it.request().params().get("permission")
                        user?.isAuthorised(permission, fun(authResult) {
                            if(authResult.succeeded() && authResult.result()) {
                                it.response().setStatusCode(200).end(json("success" to true, "permission" to permission).encodePrettily())
                            } else {
                                if(authResult.failed()) {
                                    log.error("Auth result failed with error: ", authResult.cause())
                                }
                                it.response().setStatusCode(401).end(json("success" to false, "permission" to permission).encodePrettily())
                            }
                        })
                        if(user == null) {
                            it.response().setStatusCode(401).end(json("success" to false, "permission" to permission).encodePrettily())
                        }
                    })
                    vertx.createHttpServer().requestHandler({ router.accept(it) }).listen(8000)
                    startFuture?.complete()
                })
            } else {
                startFuture?.fail("Unable to make request to $requestUrl, Server returned status code: ${httpResponse.statusCode()}")
            }
        })
    }
}

