package com.slickqa.slicker

import io.vertx.core.json.JsonObject
import javax.xml.crypto.dsig.keyinfo.KeyValue

/**
 * Created by jason.corbett on 3/3/17.
 */

fun json(vararg pairs: Pair<String, Any?>): JsonObject = JsonObject(mapOf(*pairs))
