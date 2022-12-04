package io.micronaut.function.aws.proxy;

import com.amazonaws.serverless.exceptions.ContainerInitializationException;
import com.amazonaws.serverless.proxy.AwsHttpApiV2SecurityContextWriter;
import com.amazonaws.serverless.proxy.internal.jaxrs.AwsHttpApiV2SecurityContext;
import com.amazonaws.serverless.proxy.model.AlbContext;
import com.amazonaws.serverless.proxy.model.AwsProxyResponse;
import com.amazonaws.serverless.proxy.model.CognitoAuthorizerClaims;
import com.amazonaws.serverless.proxy.model.ContainerConfig;
import com.amazonaws.serverless.proxy.model.ErrorModel;
import com.amazonaws.serverless.proxy.model.Headers;
import com.amazonaws.serverless.proxy.model.HttpApiV2AuthorizerMap;
import com.amazonaws.serverless.proxy.model.HttpApiV2HttpContext;
import com.amazonaws.serverless.proxy.model.HttpApiV2JwtAuthorizer;
import com.amazonaws.serverless.proxy.model.HttpApiV2ProxyRequest;
import com.amazonaws.serverless.proxy.model.HttpApiV2ProxyRequestContext;
import com.amazonaws.serverless.proxy.model.MultiValuedTreeMap;
import com.amazonaws.services.lambda.runtime.Context;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.databind.ObjectWriter;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.ApplicationContextBuilder;
import io.micronaut.context.ApplicationContextProvider;
import io.micronaut.core.annotation.TypeHint;
import io.micronaut.core.bind.BeanPropertyBinder;
import io.micronaut.core.type.Argument;
import io.micronaut.core.util.ArgumentUtils;
import io.micronaut.http.HttpAttributes;
import io.micronaut.http.MediaType;
import io.micronaut.http.server.RouteExecutor;
import io.micronaut.http.server.binding.RequestArgumentSatisfier;
import io.micronaut.http.server.exceptions.response.ErrorResponseProcessor;
import io.micronaut.web.router.Router;
import io.micronaut.web.router.resource.StaticResourceResolver;

import java.io.Closeable;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.function.BiFunction;

@TypeHint(
    accessType = {TypeHint.AccessType.ALL_DECLARED_CONSTRUCTORS, TypeHint.AccessType.ALL_PUBLIC},
    value = {
        AlbContext.class,
        HttpApiV2ProxyRequest.class,
        HttpApiV2HttpContext.class,
        HttpApiV2AuthorizerMap.class,
        HttpApiV2JwtAuthorizer.class,
        HttpApiV2ProxyRequestContext.class,
        AwsProxyResponse.class,
        CognitoAuthorizerClaims.class,
        ContainerConfig.class,
        ErrorModel.class,
        Headers.class,
        MultiValuedTreeMap.class,
        AwsHttpApiV2SecurityContext.class
    }
)
public class MicronautLambdaContainerHTTPV2Handler extends AbstractLambdaContainerHandler<HttpApiV2ProxyRequest, AwsProxyResponse, MicronautAwsProxyRequest<HttpApiV2ProxyRequest, ?>, MicronautAwsProxyResponse<?>> implements ApplicationContextProvider, Closeable, AutoCloseable{
    private final ApplicationContextBuilder applicationContextBuilder;
    private final LambdaContainerState lambdaContainerEnvironment;
    private final BeanPropertyBinder beanPropertyBinder;
    private ApplicationContext applicationContext;
    private RequestArgumentSatisfier requestArgumentSatisfier;
    private StaticResourceResolver resourceResolver;
    private Router router;
    private ErrorResponseProcessor errorResponseProcessor;
    private RouteExecutor routeExecutor;
    private final Map<MediaType, BiFunction<Argument<?>, String, Optional<Object>>> mediaTypeBodyDecoder = new HashMap<>();

    public MicronautLambdaContainerHTTPV2Handler(ApplicationContextBuilder applicationContextBuilder) throws ContainerInitializationException {
        this(new LambdaContainerState(), applicationContextBuilder, null);
    }

    /**
     * Default constructor.
     *
     * @throws ContainerInitializationException The exception
     */
    public MicronautLambdaContainerHTTPV2Handler() throws ContainerInitializationException {
        this(new LambdaContainerState(), ApplicationContext.builder(), null);
    }

    /**
     * Constructor used to inject a preexisting {@link ApplicationContext}.
     * @param applicationContext application context
     *
     * @throws ContainerInitializationException The exception
     */
    public MicronautLambdaContainerHTTPV2Handler(ApplicationContext applicationContext) throws ContainerInitializationException {
        this(new LambdaContainerState(), ApplicationContext.builder(), applicationContext);
    }

    /**
     * constructor.
     *
     * @param lambdaContainerEnvironment The container environment
     * @param applicationContextBuilder  The context builder
     * @throws ContainerInitializationException if the container couldn't be started
     */
    private MicronautLambdaContainerHTTPV2Handler(
        LambdaContainerState lambdaContainerEnvironment,
        ApplicationContextBuilder applicationContextBuilder,
        ApplicationContext applicationContext) throws ContainerInitializationException {
        super(
            HttpApiV2ProxyRequest.class,
            AwsProxyResponse.class,
            new MicronautHttpApiV2RequestReader(lambdaContainerEnvironment),
            new MicronautResponseWriter(lambdaContainerEnvironment),
            new AwsHttpApiV2SecurityContextWriter(),
            new MicronautAwsProxyExceptionHandler(lambdaContainerEnvironment)

        );
        ArgumentUtils.requireNonNull("applicationContextBuilder", applicationContextBuilder);
        this.lambdaContainerEnvironment = lambdaContainerEnvironment;
        this.applicationContextBuilder = applicationContextBuilder;

        if (applicationContext == null) {
            initialize();
        } else {
            this.applicationContext = applicationContext;
            initContainerState();
        }
        this.beanPropertyBinder = this.applicationContext.getBean(BeanPropertyBinder.class);
        populateMediaTypeBodyDecoders();
    }

    /**
     * constructor.
     *
     * @param lambdaContainerEnvironment The environment
     * @throws ContainerInitializationException if the container couldn't be started
     */
    private MicronautLambdaContainerHTTPV2Handler(LambdaContainerState lambdaContainerEnvironment) throws ContainerInitializationException {
        this(lambdaContainerEnvironment, ApplicationContext.builder(), null);
    }

    @Override
    public ApplicationContext getApplicationContext() {
        return applicationContext;
    }

    @Override
    protected ObjectMapper objectMapper() {
        return lambdaContainerEnvironment.getObjectMapper();
    }

    @Override
    protected ObjectWriter writerFor(Class<AwsProxyResponse> responseClass) {
        return objectMapper().writerFor(AwsProxyResponse.class);
    }

    @Override
    protected ObjectReader readerFor(Class<HttpApiV2ProxyRequest> requestClass) {
        return objectMapper().readerFor(HttpApiV2ProxyRequest.class);
    }

    @Override
    protected MicronautAwsProxyResponse<?> getContainerResponse(MicronautAwsProxyRequest<HttpApiV2ProxyRequest, ?> request, CountDownLatch latch) {
        MicronautAwsProxyResponse response = new MicronautAwsProxyResponse(
            request.getAwsProxyRequest(),
            latch,
            lambdaContainerEnvironment
        );

        Optional<Object> routeMatchAttr = request.getAttribute(HttpAttributes.ROUTE_MATCH);
        routeMatchAttr.ifPresent(o -> response.setAttribute(HttpAttributes.ROUTE_MATCH, o));

        request.setResponse(response);

        return request.getResponse();
    }

    @Override
    protected void handleRequest(MicronautAwsProxyRequest<HttpApiV2ProxyRequest, ?> containerRequest, MicronautAwsProxyResponse<?> containerResponse, Context lambdaContext) throws Exception {

    }

    @Override
    public void initialize() throws ContainerInitializationException {

    }

    @Override
    public void close() throws IOException {

    }
}
