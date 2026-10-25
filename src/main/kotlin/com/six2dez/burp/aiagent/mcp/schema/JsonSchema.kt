package com.six2dez.burp.aiagent.mcp.schema

import io.modelcontextprotocol.kotlin.sdk.Tool
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.reflect.KClass
import kotlin.reflect.KType
import kotlin.reflect.full.memberProperties
import kotlin.reflect.full.primaryConstructor

private const val MAX_SCHEMA_DEPTH = 8

fun getJsonSchemaForProperty(kType: KType): JsonElement = propertySchema(kType, 0)

private fun primitiveSchema(type: String): JsonObject = JsonObject(mapOf("type" to JsonPrimitive(type)))

private fun propertySchema(
    type: KType,
    depth: Int,
): JsonElement {
    if (depth >= MAX_SCHEMA_DEPTH) return primitiveSchema("object")
    val schema =
        when (val classifier = type.classifier) {
            String::class -> primitiveSchema("string")
            Int::class, Long::class -> primitiveSchema("integer")
            Float::class, Double::class -> primitiveSchema("number")
            Boolean::class -> primitiveSchema("boolean")
            List::class, Array::class, Set::class ->
                JsonObject(
                    mapOf(
                        "type" to JsonPrimitive("array"),
                        "items" to (
                            type.arguments
                                .firstOrNull()
                                ?.type
                                ?.let { propertySchema(it, depth + 1) } ?: primitiveSchema("object")
                        ),
                    ),
                )
            Map::class ->
                JsonObject(
                    mapOf(
                        "type" to JsonPrimitive("object"),
                        "additionalProperties" to (
                            type.arguments
                                .getOrNull(1)
                                ?.type
                                ?.let { propertySchema(it, depth + 1) } ?: primitiveSchema("object")
                        ),
                    ),
                )
            else -> classSchema(classifier as? KClass<*>, depth + 1)
        }
    return if (type.isMarkedNullable) JsonObject(mapOf("anyOf" to JsonArray(listOf(schema, primitiveSchema("null"))))) else schema
}

private fun classSchema(
    type: KClass<*>?,
    depth: Int,
): JsonObject {
    if (type?.java?.isEnum == true) {
        return JsonObject(mapOf("type" to JsonPrimitive("string"), "enum" to JsonArray(type.java.enumConstants.map { JsonPrimitive((it as Enum<*>).name) })))
    }
    return if (type?.isData != true) {
        primitiveSchema("object")
    } else {
        val (properties, required) = fields(type, depth)
        JsonObject(mapOf("type" to JsonPrimitive("object"), "properties" to properties, "required" to JsonArray(required.map { JsonPrimitive(it) })))
    }
}

private fun fields(
    type: KClass<*>,
    depth: Int,
): Pair<JsonObject, List<String>> {
    val parameters =
        type.primaryConstructor
            ?.parameters
            .orEmpty()
            .associateBy { it.name }
    val properties = type.memberProperties.associate { it.name to propertySchema(it.returnType, depth) }
    val required =
        type.memberProperties
            .filter { property ->
                property.annotations.any { it is ToolRequired } || parameters[property.name]?.let { !it.isOptional } == true
            }.map { it.name }
    return JsonObject(properties) to required
}

fun KClass<*>.asInputSchema(): Tool.Input {
    val (properties, required) = fields(this, 0)
    return Tool.Input(properties = properties, required = required)
}
