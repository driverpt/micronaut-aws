package io.micronaut.function.aws.proxy;

import com.amazonaws.serverless.proxy.internal.SecurityUtils;
import com.amazonaws.serverless.proxy.model.ApiGatewayRequestIdentity;
import com.amazonaws.serverless.proxy.model.AwsProxyRequest;
import com.amazonaws.serverless.proxy.model.AwsProxyRequestContext;
import com.amazonaws.serverless.proxy.model.ContainerConfig;
import com.amazonaws.serverless.proxy.model.Headers;
import com.amazonaws.serverless.proxy.model.MultiValuedTreeMap;
import com.amazonaws.services.lambda.runtime.Context;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.convert.ArgumentConversionContext;
import io.micronaut.core.convert.ConversionService;
import io.micronaut.core.convert.value.MutableConvertibleValues;
import io.micronaut.core.convert.value.MutableConvertibleValuesMap;
import io.micronaut.core.util.CollectionUtils;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpParameters;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.cookie.Cookies;
import io.micronaut.http.simple.SimpleHttpHeaders;
import io.micronaut.http.simple.SimpleHttpParameters;
import io.micronaut.http.simple.cookies.SimpleCookie;
import io.micronaut.http.simple.cookies.SimpleCookies;

import javax.ws.rs.core.SecurityContext;

import java.net.InetSocketAddress;
import java.net.URI;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import static com.amazonaws.serverless.proxy.RequestReader.ALB_CONTEXT_PROPERTY;
import static com.amazonaws.serverless.proxy.RequestReader.API_GATEWAY_CONTEXT_PROPERTY;
import static com.amazonaws.serverless.proxy.RequestReader.API_GATEWAY_EVENT_PROPERTY;
import static com.amazonaws.serverless.proxy.RequestReader.API_GATEWAY_STAGE_VARS_PROPERTY;
import static com.amazonaws.serverless.proxy.RequestReader.JAX_SECURITY_CONTEXT_PROPERTY;
import static com.amazonaws.serverless.proxy.RequestReader.LAMBDA_CONTEXT_PROPERTY;

public class MicronautRestApiV1Request<T> extends MicronautAwsProxyRequest<AwsProxyRequest, T> {
    private final AwsProxyRequest awsProxyRequest;
    private final HttpMethod httpMethod;
    private final MutableConvertibleValues<Object> attributes = new MutableConvertibleValuesMap<>();
    private final HttpHeaders headers;
    private final HttpParameters parameters;
    private final String path;
    private final ContainerConfig config;

    private Cookies cookies;

    /**
     * Default constructor.
     *
     * @param path            The path
     * @param awsProxyRequest The underlying request
     * @param securityContext The {@link SecurityContext}
     * @param lambdaContext   The lambda context
     * @param config          The container configuration
     */
    MicronautRestApiV1Request(String path,
                              AwsProxyRequest awsProxyRequest,
                              SecurityContext securityContext,
                              Context lambdaContext,
                              ContainerConfig config) {
        this.config = config;
        this.awsProxyRequest = awsProxyRequest;
        this.path = path;
        final String httpMethod = awsProxyRequest.getHttpMethod();
        this.httpMethod = StringUtils.isNotEmpty(httpMethod) ? HttpMethod.valueOf(httpMethod) : HttpMethod.GET;
        final Headers multiValueHeaders = awsProxyRequest.getMultiValueHeaders();
        this.headers = multiValueHeaders != null ? new AwsHeaders() : new SimpleHttpHeaders(ConversionService.SHARED);
        final MultiValuedTreeMap<String, String> params = awsProxyRequest.getMultiValueQueryStringParameters();
        this.parameters = params != null ? new AwsParameters() : new SimpleHttpParameters(ConversionService.SHARED);

        final AwsProxyRequestContext requestContext = awsProxyRequest.getRequestContext();
        setAttribute(API_GATEWAY_CONTEXT_PROPERTY, requestContext);
        setAttribute(API_GATEWAY_STAGE_VARS_PROPERTY, awsProxyRequest.getStageVariables());
        setAttribute(API_GATEWAY_EVENT_PROPERTY, awsProxyRequest);
        if (requestContext != null) {
            setAttribute(ALB_CONTEXT_PROPERTY, requestContext.getElb());
        }
        setAttribute(LAMBDA_CONTEXT_PROPERTY, lambdaContext);
        setAttribute(JAX_SECURITY_CONTEXT_PROPERTY, config);
        if (isSecurityContextPresent(securityContext)) {
            setAttribute("micronaut.AUTHENTICATION", securityContext.getUserPrincipal());
        }

    }

    @Override
    public AwsProxyRequest getUnderlyingProxyRequest() {
        return awsProxyRequest;
    }

    @Override
    public Cookies getCookies() {
        if (cookies == null) {
            SimpleCookies simpleCookies = new SimpleCookies(ConversionService.SHARED);
            getHeaders().getAll(HttpHeaders.COOKIE).forEach(cookieValue -> {
                List<HeaderValue> parsedHeaders = MicronautAwsRequestUtils.parseHeaderValue(cookieValue, ";", ",");

                parsedHeaders.stream()
                    .filter(e -> e.getKey() != null)
                    .map(e -> new SimpleCookie(SecurityUtils.crlf(e.getKey()), SecurityUtils.crlf(e.getValue())))
                    .forEach(simpleCookie ->
                        simpleCookies.put(simpleCookie.getName(), simpleCookie));
            });

            cookies = simpleCookies;
        }
        return cookies;

    }

    @Override
    public HttpParameters getParameters() {
        return parameters;
    }

    @Override
    public HttpMethod getMethod() {
        return httpMethod;
    }

    @Override
    public URI getUri() {
        String region = System.getenv("AWS_REGION");
        if (region == null) {
            // this is not a critical failure, we just put a static region in the URI
            region = "us-east-1";
        }

        final Headers multiValueHeaders = awsProxyRequest.getMultiValueHeaders();
        String hostHeader = multiValueHeaders != null ? multiValueHeaders.getFirst(HttpHeaders.HOST) : null;
        final AwsProxyRequestContext requestContext = awsProxyRequest.getRequestContext();

        if (requestContext != null && !isValidHost(hostHeader, requestContext.getApiId(), region)) {
            hostHeader = requestContext.getApiId() +
                ".execute-api." +
                region +
                ".amazonaws.com";
        }

        return URI.create(getScheme() + "://" + hostHeader + path);
    }

    @Override
    public InetSocketAddress getRemoteAddress() {
        AwsProxyRequestContext requestContext = this.awsProxyRequest.getRequestContext();
        if (Objects.isNull(requestContext)) {
            ApiGatewayRequestIdentity identity = requestContext.getIdentity();
            if (Objects.isNull(identity)) {
                final String sourceIp = identity.getSourceIp();
                return new InetSocketAddress(sourceIp, 0);
            }
        }
        return super.getRemoteAddress();
    }


    @Override
    protected String getScheme() {
        // if we don't have any headers to deduce the value we assume HTTPS - API Gateway's default
        if (Objects.isNull(awsProxyRequest.getMultiValueHeaders())) {
            return "https";
        }
        String cfScheme = awsProxyRequest.getMultiValueHeaders().getFirst(CF_PROTOCOL_HEADER_NAME);
        if (cfScheme != null && SecurityUtils.isValidScheme(cfScheme)) {
            return cfScheme;
        }
        String gwScheme = awsProxyRequest.getMultiValueHeaders().getFirst(PROTOCOL_HEADER_NAME);
        if (gwScheme != null && SecurityUtils.isValidScheme(gwScheme)) {
            return gwScheme;
        }
        // https is our default scheme
        return "https";
    }

    /**
     * Implementation of {@link HttpHeaders} for AWS.
     */
    private class AwsHeaders implements HttpHeaders {

        private Headers multiValueHeaders = awsProxyRequest.getMultiValueHeaders();

        @Override
        public List<String> getAll(CharSequence name) {
            if (StringUtils.isNotEmpty(name)) {
                final List<String> strings = multiValueHeaders.get(name.toString());
                if (CollectionUtils.isNotEmpty(strings)) {
                    return strings;
                }
            }
            return Collections.emptyList();
        }

        @Nullable
        @Override
        public String get(CharSequence name) {
            if (StringUtils.isNotEmpty(name)) {
                return multiValueHeaders.getFirst(name.toString());
            }
            return null;
        }

        @Override
        public Set<String> names() {
            return multiValueHeaders.keySet();
        }

        @Override
        public Collection<List<String>> values() {
            return multiValueHeaders.values();
        }

        @Override
        public <T> Optional<T> get(CharSequence name, ArgumentConversionContext<T> conversionContext) {
            final String v = get(name);
            if (v != null) {
                return ConversionService.SHARED.convert(v, conversionContext);
            }
            return Optional.empty();
        }
    }

    /**
     * Class that represents a header value.
     */
    public static class HeaderValue {
        private String key;
        private String value;
        private String rawValue;
        private float priority;
        private Map<String, String> attributes;

        public HeaderValue() {
            attributes = new HashMap<>();
        }

        public String getKey() {
            return key;
        }

        public void setKey(String key) {
            this.key = key;
        }

        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }

        public String getRawValue() {
            return rawValue;
        }

        public void setRawValue(String rawValue) {
            this.rawValue = rawValue;
        }

        public float getPriority() {
            return priority;
        }

        public void setPriority(float priority) {
            this.priority = priority;
        }

        public Map<String, String> getAttributes() {
            return attributes;
        }

        public void setAttributes(Map<String, String> attributes) {
            this.attributes = attributes;
        }

        public void addAttribute(String key, String value) {
            attributes.put(key, value);
        }

        public String getAttribute(String key) {
            return attributes.get(key);
        }
    }

    /**
     * Implementation of {@link HttpParameters} for AWS.
     *
     * @author graemerocher
     * @since 1.1
     */
    private class AwsParameters implements HttpParameters {

        private MultiValuedTreeMap<String, String> params = awsProxyRequest.getMultiValueQueryStringParameters();

        @Override
        public List<String> getAll(CharSequence name) {
            if (StringUtils.isNotEmpty(name)) {
                final List<String> strings = params.get(name.toString());
                if (CollectionUtils.isNotEmpty(strings)) {
                    return strings;
                }
            }
            return Collections.emptyList();
        }

        @Nullable
        @Override
        public String get(CharSequence name) {
            if (StringUtils.isNotEmpty(name)) {
                return params.getFirst(name.toString());
            }
            return null;
        }

        @Override
        public Set<String> names() {
            return params.keySet();
        }

        @Override
        public Collection<List<String>> values() {
            return params.values();
        }

        @Override
        public <T> Optional<T> get(CharSequence name, ArgumentConversionContext<T> conversionContext) {
            final String v = get(name);
            if (v != null) {
                return ConversionService.SHARED.convert(v, conversionContext);
            }
            return Optional.empty();
        }
    }
}
