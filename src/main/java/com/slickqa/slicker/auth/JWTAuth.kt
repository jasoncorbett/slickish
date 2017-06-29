package com.slickqa.slicker.auth

import io.vertx.core.AsyncResult
import io.vertx.core.Future
import io.vertx.core.Handler
import io.vertx.core.Vertx
import io.vertx.core.json.JsonArray
import io.vertx.core.json.JsonObject
import io.vertx.ext.auth.User
import io.vertx.ext.auth.jwt.impl.JWTAuthProviderImpl
import io.vertx.ext.auth.jwt.impl.JWTUser

enum class Permissions(val level: Int) {
    ADMIN(100),
    TESTER(70),
    RESTRICTED(50),
    OBSERVER(30)
}

/**
 * Created by jason.corbett on 2/11/17.
 */
class SlickJWTAuthImpl(vertx: Vertx, config: JsonObject) : JWTAuthProviderImpl(vertx, config) {
    val permissionKey: String = config.getString("permissionsClaimKey", "permissions")

    override fun authenticate(authInfo: JsonObject?, resultHandler: Handler<AsyncResult<User>>?) {
        super.authenticate(authInfo, Handler<AsyncResult<User>> {
            if(it.succeeded()) {
                var user = it.result()
                if(user is JWTUser) {
                    resultHandler?.handle(Future.succeededFuture(SlickJWTUser(user.principal(), permissionKey)))
                }
            } else {
                resultHandler?.handle(Future.failedFuture(it.cause()))
            }
        })

    }
}

fun JsonObject.getNestedArray(keyName: String): JsonArray {
    var parts = keyName.split("/")
    if(parts.size == 1) {
        return getJsonArray(parts[0])
    } else {
        var current = this
        for(i in parts.indices) {
            if(i == parts.lastIndex) {
                return current.getJsonArray(parts[i])
            } else {
                current = current.getJsonObject(parts[i])
            }
        }
    }
    // This should be unreachable code
    throw RuntimeException("Unreachable code reached, check your algorithm!")
}

val ProjectPermissionSeparator = "#!#"
val ProjectPermissionRegex = Regex(Regex.escape(ProjectPermissionSeparator))

class SlickJWTUser(jwtToken: JsonObject, permissionsClaimKey: String) : JWTUser(jwtToken, permissionsClaimKey) {

    var JWTPermissions = JsonArray()

    init {
        JWTPermissions = jwtToken.getNestedArray(permissionsClaimKey)
    }


    override fun doIsPermitted(permission: String?, handler: Handler<AsyncResult<Boolean>>?) {
        if(JWTPermissions.contains("site-admin")) {
            // site admin can do anything!
            handler?.handle(Future.succeededFuture(true))
        }
        if(permission != null) {
            if(permission.contains(ProjectPermissionSeparator)) {
                val parts = permission.split(ProjectPermissionRegex)
                val project = parts[0]
                val minimumPermission = Permissions.valueOf(parts[1])
                for(potentialMatch in JWTPermissions) {
                    if(potentialMatch is String && potentialMatch.contains(ProjectPermissionSeparator)) {
                        val potentialParts = potentialMatch.split(ProjectPermissionRegex)
                        if(project == potentialParts[0]) {
                            val potentialPermission = Permissions.valueOf(potentialParts[1])
                            if(potentialPermission.level >= minimumPermission.level) {
                                handler?.handle(Future.succeededFuture(true))
                                return
                            }
                        }
                    }
                }
            } else {
                if(JWTPermissions.contains(permission)) {
                    // not a project related permission, but they have the necessary permission
                    handler?.handle(Future.succeededFuture(true))
                }
            }
        }
        handler?.handle(Future.succeededFuture(false))
    }
}