/*
 * Copyright 2017-2020 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.function.aws.proxy;

import com.amazonaws.serverless.proxy.internal.SecurityUtils;
import com.amazonaws.serverless.proxy.internal.jaxrs.AwsHttpApiV2SecurityContext;
import com.amazonaws.serverless.proxy.internal.jaxrs.AwsProxySecurityContext;
import com.amazonaws.serverless.proxy.model.*;
import com.amazonaws.services.lambda.runtime.Context;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.convert.ArgumentConversionContext;
import io.micronaut.core.convert.ConversionService;
import io.micronaut.core.convert.value.MutableConvertibleValues;
import io.micronaut.core.convert.value.MutableConvertibleValuesMap;
import io.micronaut.core.type.Argument;
import io.micronaut.core.util.CollectionUtils;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.*;
import io.micronaut.http.cookie.Cookies;
import io.micronaut.http.simple.SimpleHttpHeaders;
import io.micronaut.http.simple.SimpleHttpParameters;
import io.micronaut.http.simple.cookies.SimpleCookie;
import io.micronaut.http.simple.cookies.SimpleCookies;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import javax.ws.rs.core.SecurityContext;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.*;

import static com.amazonaws.serverless.proxy.RequestReader.*;

/**
 * Implementation of {@link HttpRequest} that backs onto a {@link AwsProxyRequest} object.
 *
 * @param <T> The body type
 * @author graemerocher
 * @since 1.1
 */
public abstract class MicronautAwsProxyRequest<Req, T> implements HttpRequest<T> {
    public static final String HEADER_KEY_VALUE_SEPARATOR = "=";
    public static final String CF_PROTOCOL_HEADER_NAME = "CloudFront-Forwarded-Proto";
    public static final String PROTOCOL_HEADER_NAME = "X-Forwarded-Proto";

    private MicronautAwsProxyResponse<?> response;
    private T decodedBody;

    /**
     * Default constructor.
     *
     * @param path            The path
     * @param awsProxyRequest The underlying request
     * @param securityContext The {@link SecurityContext}
     * @param lambdaContext   The lambda context
     * @param config          The container configuration
     */
//    MicronautAwsProxyRequest(
//            String path,
//            AwsProxyRequest awsProxyRequest,
//            SecurityContext securityContext,
//            Context lambdaContext,
//            ContainerConfig config) {
//        this.config = config;
//        this.awsProxyRequest = awsProxyRequest;
//        this.path = path;
//        final String httpMethod = awsProxyRequest.getHttpMethod();
//        this.httpMethod = StringUtils.isNotEmpty(httpMethod) ? HttpMethod.valueOf(httpMethod) : HttpMethod.GET;
//        final Headers multiValueHeaders = awsProxyRequest.getMultiValueHeaders();
//        this.headers = multiValueHeaders != null ? new AwsHeaders() : new SimpleHttpHeaders(ConversionService.SHARED);
//        final MultiValuedTreeMap<String, String> params = awsProxyRequest.getMultiValueQueryStringParameters();
//        this.parameters = params != null ? new AwsParameters() : new SimpleHttpParameters(ConversionService.SHARED);
//
//        final AwsProxyRequestContext requestContext = awsProxyRequest.getRequestContext();
//        setAttribute(API_GATEWAY_CONTEXT_PROPERTY, requestContext);
//        setAttribute(API_GATEWAY_STAGE_VARS_PROPERTY, awsProxyRequest.getStageVariables());
//        setAttribute(API_GATEWAY_EVENT_PROPERTY, awsProxyRequest);
//        if (requestContext != null) {
//            setAttribute(ALB_CONTEXT_PROPERTY, requestContext.getElb());
//        }
//        setAttribute(LAMBDA_CONTEXT_PROPERTY, lambdaContext);
//        setAttribute(JAX_SECURITY_CONTEXT_PROPERTY, config);
//        if (isSecurityContextPresent (securityContext)) {
//            setAttribute("micronaut.AUTHENTICATION", securityContext.getUserPrincipal());
//        }
//    }

    /**
     *
     * @param securityContext Security Context
     * @return returns false if the security context is not present, the associated event is null or the event's request context is null
     */
    static boolean isSecurityContextPresent(@Nullable SecurityContext securityContext) {
        if (securityContext == null) {
            return false;
        }
        if (securityContext instanceof AwsProxySecurityContext) {
            AwsProxySecurityContext awsProxySecurityContext = (AwsProxySecurityContext) securityContext;
            if (awsProxySecurityContext.getEvent() == null ||
                    awsProxySecurityContext.getEvent().getRequestContext() == null ||
                    awsProxySecurityContext.getEvent().getRequestContext().getIdentity() == null) {
                           return false;
            }
        }
        if (securityContext instanceof AwsHttpApiV2SecurityContext) {
            AwsHttpApiV2SecurityContext context =
                (AwsHttpApiV2SecurityContext) securityContext;
            return context.getUserPrincipal() != null;
        }
        return true;
    }

    /**
     * The backing {@link AwsProxyRequest} object.
     *
     * @return The backing {@link AwsProxyRequest} object.
     */
    public abstract Req getUnderlyingProxyRequest();

    /**
     * @return The response object
     */
    @Internal
    public MicronautAwsProxyResponse<?> getResponse() {
        if (response == null) {
            throw new IllegalStateException("Response not set");
        }
        return response;
    }

    /**
     * Sets the associated response object.
     *
     * @param response The response
     */
    @Internal
    void setResponse(MicronautAwsProxyResponse<?> response) {
        this.response = response;
    }

    @Override
    @NonNull
    public abstract Cookies getCookies();

    @Override
    @NonNull
    public abstract HttpParameters getParameters();

    @Override
    @NonNull
    public abstract HttpMethod getMethod();

    @Override
    @NonNull
    public abstract URI getUri();

    protected abstract String getScheme();


    protected boolean isValidHost(String host, String apiId, String region) {
        if (host == null) {
            return false;
        }
        if (host.endsWith(".amazonaws.com")) {
            String defaultHost = apiId +
                    ".execute-api." +
                    region +
                    ".amazonaws.com";
            return host.equals(defaultHost);
        } else {
            return config.getCustomDomainNames().contains(host);
        }
    }

    @NonNull
    @Override
    public Optional<MediaType> getContentType() {
        Optional<MediaType> specifiedType = HttpRequest.super.getContentType();
        if (specifiedType.isPresent()) {
            return specifiedType;
        } else {
            return Optional.of(MediaType.APPLICATION_JSON_TYPE);
        }
    }

    @Override
    @NonNull
    public HttpHeaders getHeaders() {
        return headers;
    }

    @Override
    @NonNull
    public MutableConvertibleValues<Object> getAttributes() {
        return attributes;
    }

    @SuppressWarnings("unchecked")
    @Override
    @NonNull
    public Optional<T> getBody() {
        if (decodedBody != null) {
            return Optional.of(decodedBody);
        }
        final String body = awsProxyRequest.getBody();
        if (awsProxyRequest.isBase64Encoded() && body != null) {
            return (Optional<T>) Optional.ofNullable(Base64.getMimeDecoder().decode(body));
        }
        return (Optional<T>) Optional.ofNullable(body);
    }

    @Override
    @NonNull
    public <T1> Optional<T1> getBody(Argument<T1> type) {
        if (decodedBody != null) {
            return ConversionService.SHARED.convert(decodedBody, type);
        }
        final String body = awsProxyRequest.getBody();
        if (body != null) {
            if (awsProxyRequest.isBase64Encoded()) {
                byte[] bytes = Base64.getMimeDecoder().decode(body);
                if (type.getType().isInstance(bytes)) {
                    return (Optional<T1>) Optional.of(bytes);
                }
                return ConversionService.SHARED.convert(bytes, type);
            }
            if (type.getType().isInstance(body)) {
                return (Optional<T1>) Optional.of(body);
            } else {
                final byte[] bytes = body.getBytes(getCharacterEncoding());
                return ConversionService.SHARED.convert(bytes, type);
            }
        }
        return Optional.empty();
    }

    /**
     * Generic method to parse an HTTP header value and split it into a list of key/values for all its components.
     * When the property in the header does not specify a key the key field in the output pair is null and only the value
     * is populated. For example, The header <code>Accept: application/json; application/xml</code> will contain two
     * key value pairs with key null and the value set to application/json and application/xml respectively.
     *
     * @param headerValue        The string value for the HTTP header
     * @param valueSeparator     The separator to be used for parsing header values
     * @param qualifierSeparator the qualifier separator
     * @return A list of SimpleMapEntry objects with all of the possible values for the header.
     */


    /**
     * The decoded body.
     *
     * @param decodedBody The body
     */
    @Internal
    void setDecodedBody(T decodedBody) {
        this.decodedBody = decodedBody;
    }

    /**
     * @return true if body was already decoded, false otherwise
     */
    public boolean isBodyDecoded() {
        return decodedBody != null;
    }

}
