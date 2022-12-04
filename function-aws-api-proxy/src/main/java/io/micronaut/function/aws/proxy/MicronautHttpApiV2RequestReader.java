package io.micronaut.function.aws.proxy;

import com.amazonaws.serverless.exceptions.InvalidRequestEventException;
import com.amazonaws.serverless.proxy.RequestReader;
import com.amazonaws.serverless.proxy.model.AwsProxyRequest;
import com.amazonaws.serverless.proxy.model.ContainerConfig;
import com.amazonaws.serverless.proxy.model.HttpApiV2ProxyRequest;
import com.amazonaws.services.lambda.runtime.Context;
import io.micronaut.core.annotation.Internal;
import io.micronaut.http.HttpAttributes;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.web.router.UriRoute;
import io.micronaut.web.router.UriRouteMatch;

import javax.ws.rs.core.SecurityContext;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static io.micronaut.http.HttpAttributes.AVAILABLE_HTTP_METHODS;
import static io.micronaut.http.HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD;

@Internal
class MicronautHttpApiV2RequestReader extends RequestReader<HttpApiV2ProxyRequest, MicronautAwsProxyRequest<?>> {

    private final MicronautLambdaContainerContext environment;
    /**
     * Default constructor.
     *
     * @param environment The {@link MicronautLambdaContainerContext}
     */
    MicronautHttpApiV2RequestReader(MicronautLambdaContainerContext environment) {
        this.environment = environment;
    }
    @Override
    public MicronautAwsProxyRequest<?> readRequest(
        HttpApiV2ProxyRequest request,
        SecurityContext securityContext,
        Context lambdaContext,
        ContainerConfig config) throws InvalidRequestEventException {

        try {
            final String path = config.isStripBasePath() ? stripBasePath(request.getPath(), config) : getPathNoBase(request);
            final MicronautAwsProxyRequest<?> containerRequest = new MicronautHtt<>(
                path,
                request,
                securityContext,
                lambdaContext,
                config
            );

            List<UriRouteMatch<Object, Object>> uriRoutes = environment.getRouter().findAllClosest(containerRequest);

            if (uriRoutes.isEmpty() && isPreflightRequest(containerRequest)) {
                List<UriRouteMatch<Object, Object>> anyUriRoutes = environment.getRouter().findAny(containerRequest.getUri().getPath(), containerRequest)
                    .collect(Collectors.toList());
                containerRequest.setAttribute(AVAILABLE_HTTP_METHODS, anyUriRoutes.stream().map(UriRouteMatch::getHttpMethod).collect(Collectors.toList()));
            } else if (!uriRoutes.isEmpty()) {
                UriRouteMatch<Object, Object> finalRoute = uriRoutes.get(0);
                final UriRoute route = finalRoute.getRoute();
                containerRequest.setAttribute(HttpAttributes.ROUTE, route);
                containerRequest.setAttribute(HttpAttributes.ROUTE_MATCH, finalRoute);
                containerRequest.setAttribute(HttpAttributes.ROUTE_INFO, finalRoute);
                containerRequest.setAttribute(HttpAttributes.URI_TEMPLATE, route.getUriMatchTemplate().toString());
            }
            return containerRequest;
        } catch (Exception e) {
            throw new InvalidRequestEventException("Invalid Request: " + e.getMessage(), e);
        }
    }

    @Override
    protected Class<? extends HttpApiV2ProxyRequest> getRequestClass() {
        return HttpApiV2ProxyRequest.class;
    }

    static boolean isPreflightRequest(HttpRequest<?> request) {
        HttpHeaders headers = request.getHeaders();
        Optional<String> origin = headers.getOrigin();
        return origin.isPresent() && headers.contains(ACCESS_CONTROL_REQUEST_METHOD) && HttpMethod.OPTIONS == request.getMethod();
    }

    private static String getPathNoBase(AwsProxyRequest request) {
        if (request.getResource() == null || "".equals(request.getResource())) {
            return request.getPath();
        }

        if (request.getPathParameters() == null || request.getPathParameters().isEmpty()) {
            return request.getResource();
        }

        String path = request.getResource();
        for (Map.Entry<String, String> variable : request.getPathParameters().entrySet()) {
            path = path.replaceAll("\\{" + Pattern.quote(variable.getKey()) + "\\+?}", variable.getValue());
        }

        return path;
    }
}
