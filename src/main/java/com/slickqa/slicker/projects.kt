package com.slickqa.slicker

import org.litote.kmongo.MongoId

/**
 * Created by jason.corbett on 3/3/17.
 */

data class Project(@MongoId var id: String? = null,
                   var name: String = "",
                   var description: String? = null)
