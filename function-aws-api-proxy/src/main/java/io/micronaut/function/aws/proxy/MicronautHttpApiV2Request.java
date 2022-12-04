package io.micronaut.function.aws.proxy;

import com.amazonaws.serverless.proxy.internal.SecurityUtils;
import com.amazonaws.serverless.proxy.model.AwsProxyRequestContext;
import com.amazonaws.serverless.proxy.model.ContainerConfig;
import com.amazonaws.serverless.proxy.model.Headers;
import com.amazonaws.serverless.proxy.model.HttpApiV2ProxyRequest;
import com.amazonaws.serverless.proxy.model.HttpApiV2ProxyRequestContext;
import com.amazonaws.services.lambda.runtime.Context;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.convert.ConversionService;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpParameters;
import io.micronaut.http.cookie.Cookies;
import io.micronaut.http.simple.SimpleHttpParameters;
import io.micronaut.http.simple.cookies.SimpleCookie;
import io.micronaut.http.simple.cookies.SimpleCookies;

import java.net.HttpCookie;
import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import static com.amazonaws.serverless.proxy.RequestReader.ALB_CONTEXT_PROPERTY;
import static com.amazonaws.serverless.proxy.RequestReader.API_GATEWAY_CONTEXT_PROPERTY;
import static com.amazonaws.serverless.proxy.RequestReader.API_GATEWAY_EVENT_PROPERTY;
import static com.amazonaws.serverless.proxy.RequestReader.API_GATEWAY_STAGE_VARS_PROPERTY;
import static com.amazonaws.serverless.proxy.RequestReader.JAX_SECURITY_CONTEXT_PROPERTY;
import static com.amazonaws.serverless.proxy.RequestReader.LAMBDA_CONTEXT_PROPERTY;

public class MicronautHttpApiV2Request<T> extends MicronautAwsProxyRequest<HttpApiV2ProxyRequest, T> {
    private final HttpApiV2ProxyRequest request;
    private final Context context;
    private final ContainerConfig config;
    private Cookies cachedCookies;
    private HttpParameters cachedQueryParameters;

    MicronautHttpApiV2Request(HttpApiV2ProxyRequest request,
                              Context lambdaContext,
                              ContainerConfig config) {
        this.request = request;
        this.context = lambdaContext;
        this.config = config;

        final HttpApiV2ProxyRequestContext requestContext = request.getRequestContext();
        setAttribute(API_GATEWAY_CONTEXT_PROPERTY, requestContext);
        setAttribute(API_GATEWAY_STAGE_VARS_PROPERTY, request.getStageVariables());
        setAttribute(API_GATEWAY_EVENT_PROPERTY, request);

        request.getRequestContext().getAuthorizer().
        setAttribute(LAMBDA_CONTEXT_PROPERTY, lambdaContext);
        setAttribute(JAX_SECURITY_CONTEXT_PROPERTY, config);
        if (Objects.nonNull(requestContext) &&
            Objects.nonNull(requestContext.getAuthorizer())
            && isSecurityContextPresent(securityContext)) {
            setAttribute("micronaut.AUTHENTICATION", securityContext.getUserPrincipal());
        }
    }

    @Override
    public HttpApiV2ProxyRequest getUnderlyingProxyRequest() {
        return request;
    }

    @Override
    public Cookies getCookies() {
        if (cachedCookies == null) {
            SimpleCookies simpleCookies = new SimpleCookies(ConversionService.SHARED);
            request.getCookies().forEach(cookieValue -> {
                List<HttpCookie> parsedCookie = HttpCookie.parse(cookieValue);
                parsedCookie.stream()
                    .map(cookie ->
                        new SimpleCookie(cookie.getName(), cookie.getValue())
                            .maxAge(cookie.getMaxAge())
                            .domain(cookie.getDomain())
                            .path(cookie.getPath())
                            .httpOnly(cookie.isHttpOnly())
                            .secure(cookie.getSecure()))
                    .forEach(cookie -> simpleCookies.put(cookie.getName(), cookie));
            });
            cachedCookies = simpleCookies;
        }

        return cachedCookies;
    }

    @Override
    @NonNull
    public HttpParameters getParameters() {
        if (cachedQueryParameters == null) {
            Map<CharSequence, List<String>> queryParameters = request.getQueryStringParameters()
                .entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey,
                        entry -> Arrays
                            .stream(entry.getValue().split(","))
                            .collect(Collectors.toList())));
            cachedQueryParameters = new SimpleHttpParameters(queryParameters, ConversionService.SHARED);
        }

        return cachedQueryParameters;
    }

    @Override
    @NonNull
    public HttpMethod getMethod() {
        return HttpMethod.parse(request.getRequestContext().getHttp().getMethod());
    }

    @Override
    public URI getUri() {
        String region = System.getenv("AWS_REGION");
        if (region == null) {
            // this is not a critical failure, we just put a static region in the URI
            region = "us-east-1";
        }

        final Map<String, String> headers = request.getHeaders();
        String hostHeader = Optional.ofNullable(headers.get(HttpHeaders.HOST))
                .flatMap(host -> Arrays.stream(host.split(",")).findFirst())
                .orElse(null);

        final HttpApiV2ProxyRequestContext requestContext = request.getRequestContext();
        if (Objects.nonNull(requestContext) && !isValidHost(hostHeader, requestContext.getApiId(), region)) {
            hostHeader = requestContext.getApiId() +
                ".execute-api." +
                region +
                ".amazonaws.com";
        }

        return URI.create(getScheme() + "://" + hostHeader + request.getRawPath() + "?" + request.getRawQueryString());
    }

    @Override
    protected String getScheme() {
        // if we don't have any headers to deduce the value we assume HTTPS - API Gateway's default
        if (Objects.isNull(request.getHeaders()) || request.getHeaders().isEmpty()) {
            return "https";
        }
        String cfScheme = request.getHeaders().get(CF_PROTOCOL_HEADER_NAME);
        if (Objects.nonNull(cfScheme) && SecurityUtils.isValidScheme(cfScheme)) {
            return cfScheme;
        }
        String gwScheme = request.getHeaders().get(PROTOCOL_HEADER_NAME);
        if (Objects.nonNull(gwScheme) && SecurityUtils.isValidScheme(gwScheme)) {
            return gwScheme;
        }
        // https is our default scheme
        return "https";
    }

}
