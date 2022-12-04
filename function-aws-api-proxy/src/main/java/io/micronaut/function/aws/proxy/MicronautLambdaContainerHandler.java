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

import com.amazonaws.serverless.exceptions.ContainerInitializationException;
import com.amazonaws.serverless.proxy.AwsProxySecurityContextWriter;
import com.amazonaws.serverless.proxy.internal.jaxrs.AwsProxySecurityContext;
import com.amazonaws.serverless.proxy.internal.testutils.Timer;
import com.amazonaws.serverless.proxy.model.*;
import com.amazonaws.services.lambda.runtime.Context;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.databind.ObjectWriter;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.ApplicationContextBuilder;
import io.micronaut.context.ApplicationContextProvider;
import io.micronaut.core.annotation.AnnotationMetadata;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.annotation.TypeHint;
import io.micronaut.core.async.publisher.Publishers;
import io.micronaut.core.async.subscriber.CompletionAwareSubscriber;
import io.micronaut.core.bind.BeanPropertyBinder;
import io.micronaut.core.convert.exceptions.ConversionErrorException;
import io.micronaut.core.convert.value.ConvertibleValues;
import io.micronaut.core.convert.value.ConvertibleValuesMap;
import io.micronaut.core.type.Argument;
import io.micronaut.core.type.TypeVariableResolver;
import io.micronaut.core.util.ArgumentUtils;
import io.micronaut.core.util.CollectionUtils;
import io.micronaut.core.util.StringUtils;
import io.micronaut.function.aws.HandlerUtils;
import io.micronaut.function.aws.LambdaApplicationContextBuilder;
import io.micronaut.http.HttpAttributes;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Consumes;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.annotation.Status;
import io.micronaut.http.bind.RequestBinderRegistry;
import io.micronaut.http.context.ServerRequestContext;
import io.micronaut.http.server.HttpServerConfiguration;
import io.micronaut.http.server.RouteExecutor;
import io.micronaut.http.server.binding.RequestArgumentSatisfier;
import io.micronaut.http.server.exceptions.response.ErrorContext;
import io.micronaut.http.server.exceptions.response.ErrorResponseProcessor;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.jackson.codec.JsonMediaTypeCodec;
import io.micronaut.scheduling.executor.ExecutorSelector;
import io.micronaut.web.router.MethodBasedRouteMatch;
import io.micronaut.web.router.RouteInfo;
import io.micronaut.web.router.RouteMatch;
import io.micronaut.web.router.Router;
import io.micronaut.web.router.UriRouteMatch;
import io.micronaut.web.router.resource.StaticResourceResolver;
import org.reactivestreams.Publisher;
import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.io.Closeable;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Main entry for AWS API proxy with Micronaut.
 *
 * @author graemerocher
 * @since 1.1
 */
@TypeHint(
    accessType = {TypeHint.AccessType.ALL_DECLARED_CONSTRUCTORS, TypeHint.AccessType.ALL_PUBLIC},
    value = {
        AlbContext.class,
        ApiGatewayAuthorizerContext.class,
        ApiGatewayRequestIdentity.class,
        AwsProxyRequest.class,
        AwsProxyRequestContext.class,
        AwsProxyResponse.class,
        CognitoAuthorizerClaims.class,
        ContainerConfig.class,
        ErrorModel.class,
        Headers.class,
        MultiValuedTreeMap.class,
        AwsProxySecurityContext.class
    }
)
public final class MicronautLambdaContainerHandler
    extends AbstractLambdaContainerHandler<AwsProxyRequest, AwsProxyResponse, MicronautAwsProxyRequest<AwsProxyRequest, ?>, MicronautAwsProxyResponse<?>> implements ApplicationContextProvider, Closeable, AutoCloseable {

    private static final Logger LOG = LoggerFactory.getLogger(MicronautLambdaContainerHandler.class);
    private static final String TIMER_INIT = "MICRONAUT_COLD_START";
    private static final String TIMER_REQUEST = "MICRONAUT_HANDLE_REQUEST";
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

    /**
     * Default constructor.
     *
     * @param applicationContextBuilder The context builder
     * @throws ContainerInitializationException The exception
     */
    public MicronautLambdaContainerHandler(ApplicationContextBuilder applicationContextBuilder) throws ContainerInitializationException {
        this(new LambdaContainerState(), applicationContextBuilder, null);
    }

    /**
     * Default constructor.
     *
     * @throws ContainerInitializationException The exception
     */
    public MicronautLambdaContainerHandler() throws ContainerInitializationException {
        this(new LambdaContainerState(), ApplicationContext.builder(), null);
    }

    /**
     * Constructor used to inject a preexisting {@link ApplicationContext}.
     *
     * @param applicationContext application context
     * @throws ContainerInitializationException The exception
     */
    public MicronautLambdaContainerHandler(ApplicationContext applicationContext) throws ContainerInitializationException {
        this(new LambdaContainerState(), ApplicationContext.builder(), applicationContext);
    }

    /**
     * constructor.
     *
     * @param lambdaContainerEnvironment The container environment
     * @param applicationContextBuilder  The context builder
     * @throws ContainerInitializationException if the container couldn't be started
     */
    private MicronautLambdaContainerHandler(
        LambdaContainerState lambdaContainerEnvironment,
        ApplicationContextBuilder applicationContextBuilder,
        ApplicationContext applicationContext) throws ContainerInitializationException {
        super(
            AwsProxyRequest.class,
            AwsProxyResponse.class,
            new MicronautRequestReader(lambdaContainerEnvironment),
            new MicronautResponseWriter(lambdaContainerEnvironment),
            new AwsProxySecurityContextWriter(),
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
    private MicronautLambdaContainerHandler(LambdaContainerState lambdaContainerEnvironment) throws ContainerInitializationException {
        this(lambdaContainerEnvironment, ApplicationContext.builder(), null);
    }

    /**
     * @return The underlying application context
     */
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
        return objectMapper().writerFor(responseClass);
    }

    @Override
    protected ObjectReader readerFor(Class<AwsProxyRequest> requestClass) {
        return objectMapper().readerFor(requestClass);
    }

    @Override
    protected MicronautAwsProxyResponse<?> getContainerResponse(
        MicronautAwsProxyRequest<AwsProxyRequest, ?> request,
        CountDownLatch latch) {
        MicronautAwsProxyResponse<?> response = new MicronautAwsProxyResponse<>(
            request,
            latch,
            lambdaContainerEnvironment
        );

        Optional<Object> routeMatchAttr = request.getAttribute(HttpAttributes.ROUTE_MATCH);
        routeMatchAttr.ifPresent(o -> response.setAttribute(HttpAttributes.ROUTE_MATCH, o));

        request.setResponse(response);

        return request.getResponse();
    }

    @Override
    public void initialize() throws ContainerInitializationException {
        Timer.start(TIMER_INIT);
        try {
            LambdaApplicationContextBuilder.setLambdaConfiguration(applicationContextBuilder);
            this.applicationContext = applicationContextBuilder.build().start();
            initContainerState();
        } catch (Exception e) {
            throw new ContainerInitializationException(
                "Error starting Micronaut container: " + e.getMessage(),
                e
            );
        }
        Timer.stop(TIMER_INIT);
    }

    protected void initContainerState() {
        this.lambdaContainerEnvironment.setApplicationContext(applicationContext);
        this.lambdaContainerEnvironment.setJsonCodec(applicationContext.getBean(JsonMediaTypeCodec.class));
        this.lambdaContainerEnvironment.setRouter(applicationContext.getBean(Router.class));

        Optional<ObjectMapper> objectMapper = applicationContext.findBean(ObjectMapper.class, Qualifiers.byName("aws"));
        if (objectMapper.isPresent()) {
            lambdaContainerEnvironment.setObjectMapper(objectMapper.get());
        } else {
            lambdaContainerEnvironment.setObjectMapper(applicationContext.getBean(ObjectMapper.class));
        }

        this.requestArgumentSatisfier = new RequestArgumentSatisfier(
            applicationContext.getBean(RequestBinderRegistry.class)
        );
        this.resourceResolver = applicationContext.getBean(StaticResourceResolver.class);
        addConverters();

        this.router = lambdaContainerEnvironment.getRouter();
        this.errorResponseProcessor = applicationContext.getBean(ErrorResponseProcessor.class);
        HttpServerConfiguration serverConfiguration = applicationContext.getBean(HttpServerConfiguration.class);
        ExecutorSelector executorSelector = applicationContext.getBean(ExecutorSelector.class);

        this.routeExecutor = new RouteExecutor(
            this.router,
            applicationContext,
            requestArgumentSatisfier,
            serverConfiguration,
            errorResponseProcessor,
            executorSelector
        );
    }

    /**
     * Add converters to the Application environment.
     */
    protected void addConverters() {
        addByteArrayToStringConverter();
    }

    /**
     * Adds a converter from byte array to string.
     */
    protected void addByteArrayToStringConverter() {
        applicationContext.getEnvironment().addConverter(
            byte[].class, String.class, bytes -> new String(bytes, StandardCharsets.UTF_8)
        );
    }

    @Override
    protected void handleRequest(
        MicronautAwsProxyRequest<AwsProxyRequest, ?> containerRequest,
        MicronautAwsProxyResponse<?> containerResponse,
        Context lambdaContext) {
        Timer.start(TIMER_REQUEST);
        HandlerUtils.configureWithContext(this, lambdaContext);

        try {
            ServerRequestContext.with(containerRequest, () -> {
                Optional<UriRouteMatch> routeMatch = containerRequest.getAttribute(HttpAttributes.ROUTE_MATCH, UriRouteMatch.class);

                if (!routeMatch.isPresent()) {
                    handlePossibleErrorStatus(containerRequest, containerResponse);
                    return;
                }

                handleRouteMatch(routeMatch.get(), containerRequest, containerResponse);
            });
        } finally {
            Timer.stop(TIMER_REQUEST);
        }
    }

    private void handleRouteMatch(
        RouteMatch<?> originalRoute,
        MicronautAwsProxyRequest<AwsProxyRequest, ?> request,
        MicronautAwsProxyResponse<?> response
    ) {
        final AnnotationMetadata annotationMetadata = originalRoute.getAnnotationMetadata();
        annotationMetadata.stringValue(Produces.class)
            .map(MediaType::new)
            .ifPresent(response::contentType);

        Flux<MutableHttpResponse<?>> routeResponse;
        try {
            decodeRequestBody(request, originalRoute)
                .ifPresent(((MicronautAwsProxyRequest) request)::setDecodedBody
                );

            RouteMatch<?> route = requestArgumentSatisfier.fulfillArgumentRequirements(originalRoute, request, false);

            Flux<RouteMatch<?>> routeMatchPublisher = Flux.just(route);

            routeResponse = routeExecutor.executeRoute(
                request,
                true,
                routeMatchPublisher
            ).mapNotNull(r -> convertResponseBody(response, r.getAttribute(HttpAttributes.ROUTE_INFO, RouteInfo.class).get(), r.body()).block());
        } catch (Exception e) {
            routeResponse = Flux.from(routeExecutor.filterPublisher(new AtomicReference<>(request), routeExecutor.onError(e, request)));
        }

        routeResponse
            .contextWrite(ctx -> ctx.put(ServerRequestContext.KEY, request))
            .subscribe(new CompletionAwareSubscriber<HttpResponse<?>>() {
                @Override
                protected void doOnSubscribe(Subscription subscription) {
                    subscription.request(1);
                }

                @Override
                protected void doOnNext(HttpResponse<?> message) {
                    toAwsProxyResponse(response, message);
                    subscription.request(1);
                }

                @Override
                protected void doOnError(Throwable throwable) {
                    try {
                        final MutableHttpResponse<?> defaultErrorResponse = routeExecutor.createDefaultErrorResponse(request, throwable);
                        toAwsProxyResponse(response, defaultErrorResponse);
                    } finally {
                        response.close();
                    }
                }

                @Override
                protected void doOnComplete() {
                    response.close();
                }
            });
    }

    private MicronautAwsProxyResponse<?> toAwsProxyResponse(
        MicronautAwsProxyResponse<?> response,
        HttpResponse<?> message) {
        if (response != message) {
            response.status(message.status(), message.status().getReason());
            response.body(message.body());
            message.getHeaders().forEach((name, value) -> {
                for (String val : value) {
                    response.header(name, val);
                }
            });
            response.getAttributes().putAll(message.getAttributes());
        }

        return response;
    }

    private void populateMediaTypeBodyDecoders() {
        mediaTypeBodyDecoder.put(MediaType.APPLICATION_JSON_TYPE, this::getJsonDecodedBody);
        mediaTypeBodyDecoder.put(MediaType.APPLICATION_FORM_URLENCODED_TYPE, this::getFormUrlEncodedDecodedBody);
    }

    @NonNull
    private static Optional<String> parseUndecodedBody(
        @NonNull MicronautAwsProxyRequest<AwsProxyRequest, ?> containerRequest,
        @NonNull RouteMatch<?> finalRoute,
        @NonNull MediaType mediaType) {
        if (containerRequest.isBodyDecoded()) {
            return Optional.empty();
        }
        if (!HttpMethod.permitsRequestBody(containerRequest.getMethod())) {
            return Optional.empty();
        }
        final MediaType requestContentType = containerRequest.getContentType().orElse(null);
        if (requestContentType == null) {
            return Optional.empty();
        }
        if (!mediaType.getExtension().equals(requestContentType.getExtension())) {
            return Optional.empty();
        }
        final MediaType[] expectedContentType = finalRoute.getAnnotationMetadata().getValue(Consumes.class, MediaType[].class).orElse(null);
        return (expectedContentType == null || Arrays.stream(expectedContentType).anyMatch(ct -> mediaType.getExtension().equals(ct.getExtension()))) ?
            containerRequest.getBody(String.class) :
            Optional.empty();
    }

    @NonNull
    private Optional<Object> decodeRequestBody(
        @NonNull MicronautAwsProxyRequest<AwsProxyRequest, ?> containerRequest,
        @NonNull RouteMatch<?> finalRoute) {
        return mediaTypeBodyDecoder.entrySet()
            .stream()
            .map(e -> decodeRequestBody(containerRequest, finalRoute, e))
            .filter(Optional::isPresent)
            .map(Optional::get)
            .findFirst();
    }

    private static Optional<Object> decodeRequestBody(
        @NonNull MicronautAwsProxyRequest<AwsProxyRequest, ?> containerRequest,
        @NonNull RouteMatch<?> finalRoute,
        @NonNull Map.Entry<MediaType, BiFunction<Argument<?>, String, Optional<Object>>> entry) {
        return parseUndecodedBody(containerRequest, finalRoute, entry.getKey())
            .flatMap(body -> decodeRequestBody(body, entry.getValue(), finalRoute));
    }

    @NonNull
    private static Optional<Object> decodeRequestBody(@NonNull String body,
                                                      @NonNull BiFunction<Argument<?>, String, Optional<Object>> function,
                                                      @NonNull RouteMatch<?> finalRoute) {
        if (StringUtils.isNotEmpty(body)) {
            Argument<?> bodyArgument = parseBodyArgument(finalRoute);
            return function.apply(bodyArgument, body);
        }
        return Optional.empty();
    }

    @Nullable
    private static Argument<?> parseBodyArgument(@NonNull RouteMatch<?> finalRoute) {
        Argument<?> bodyArgument = finalRoute.getBodyArgument().orElse(null);
        if (bodyArgument == null) {
            if (finalRoute instanceof MethodBasedRouteMatch) {
                bodyArgument = Arrays.stream(((MethodBasedRouteMatch) finalRoute).getArguments())
                    .filter(arg -> HttpRequest.class.isAssignableFrom(arg.getType()))
                    .findFirst()
                    .flatMap(TypeVariableResolver::getFirstTypeVariable).orElse(null);
            }
        }
        if (bodyArgument != null) {
            final Class<?> rawType = bodyArgument.getType();
            if (Publishers.isConvertibleToPublisher(rawType) || HttpRequest.class.isAssignableFrom(rawType)) {
                bodyArgument = bodyArgument.getFirstTypeVariable().orElse(Argument.OBJECT_ARGUMENT);
            }
        }
        return bodyArgument;
    }

    @NonNull
    private Optional<Object> getFormUrlEncodedDecodedBody(@Nullable Argument<?> bodyArgument,
                                                          @NonNull String body) {
        if (bodyArgument == null) {
            JsonNode encodedValues = lambdaContainerEnvironment.getObjectMapper().valueToTree(formUrlEncodedBodyToConvertibleValues(body));
            return Optional.ofNullable(encodedValues);
        }
        if (nestedBody(bodyArgument)) {
            return Optional.ofNullable(formUrlEncodedBodyToConvertibleValues(body));
        }
        return bindFormUrlEncoded(bodyArgument, body);
    }

    @NonNull
    private Optional<Object> getJsonDecodedBody(@Nullable Argument<?> bodyArgument,
                                                @NonNull String body) {

        if (bodyArgument == null) {
            JsonMediaTypeCodec jsonCodec = lambdaContainerEnvironment.getJsonCodec();
            JsonNode decoded = jsonCodec.decode(JsonNode.class, body);
            return Optional.of(decoded);
        }
        JsonMediaTypeCodec jsonCodec = lambdaContainerEnvironment.getJsonCodec();
        if (nestedBody(bodyArgument)) {
            return Optional.of(new ConvertibleValuesMap(jsonCodec.decode(Argument.of(Map.class), body)));
        }
        return Optional.of(jsonCodec.decode(bodyArgument, body));
    }

    @NonNull
    private static Optional<Map<String, List<String>>> formUrlEncodedBodyToMap(@NonNull String body) {
        QueryStringDecoder decoder = new QueryStringDecoder(body, false);
        Map<String, List<String>> parameters = decoder.parameters();
        return CollectionUtils.isEmpty(parameters) ? Optional.empty() :
            Optional.of(parameters);
    }

    @Nullable
    private static ConvertibleValues<?> formUrlEncodedBodyToConvertibleValues(@NonNull String body) {
        return formUrlEncodedBodyToMap(body)
            .map(ConvertibleValuesMap::new)
            .orElse(null);
    }

    private static boolean nestedBody(@NonNull Argument<?> bodyArgument) {
        AnnotationMetadata annotationMetadata = bodyArgument.getAnnotationMetadata();
        if (annotationMetadata.hasAnnotation(Body.class)) {
            return annotationMetadata.stringValue(Body.class).isPresent();
        }
        return false;
    }

    @NonNull
    private Optional<Object> bindFormUrlEncoded(@NonNull Argument<?> argument, @NonNull String formUrlEncodedString) {
        return formUrlEncodedBodyToMap(formUrlEncodedString)
            .flatMap(parameters -> bindFormUrlEncoded(argument, parameters));
    }

    @NonNull
    private Optional<Object> bindFormUrlEncoded(@NonNull Argument<?> argument, @NonNull Map<String, List<String>> bodyParameters) {
        Map<CharSequence, Object> source = new HashMap<>();
        for (Map.Entry<String, List<String>> entry : bodyParameters.entrySet()) {
            source.put(entry.getKey(), entry.getValue());
        }
        try {
            return Optional.of(beanPropertyBinder.bind(argument.getType(), source));
        } catch (ConversionErrorException e) {
            if (LOG.isErrorEnabled()) {
                LOG.error("Unable to convert to {}", argument.getType().getSimpleName(), e);
            }
            return Optional.empty();
        }
    }

    private Mono<MutableHttpResponse<?>> convertResponseBody(
        MicronautAwsProxyResponse<?> containerResponse,
        RouteInfo<?> routeInfo,
        Object body) {
        if (Publishers.isConvertibleToPublisher(body)) {
            Mono<?> single;
            if (Publishers.isSingle(body.getClass()) || routeInfo.getReturnType().isSpecifiedSingle()) {
                single = Mono.from(Publishers.convertPublisher(body, Publisher.class));
            } else {
                single = Flux.from(Publishers.convertPublisher(body, Publisher.class)).collectList();
            }
            return single.map((Function<Object, MutableHttpResponse<?>>) o -> {
                if (!(o instanceof MicronautAwsProxyResponse)) {
                    ((MutableHttpResponse) containerResponse).body(o);
                }
                applyRouteConfig(containerResponse, routeInfo);
                return containerResponse;
            });
        } else {
            if (!(body instanceof MicronautAwsProxyResponse)) {
                applyRouteConfig(containerResponse, routeInfo);
                ((MutableHttpResponse) containerResponse).body(body);
            }
            return Mono.just(containerResponse);
        }
    }

    private void applyRouteConfig(MicronautAwsProxyResponse<?> containerResponse, RouteInfo<?> finalRoute) {
        if (!containerResponse.getContentType().isPresent()) {
            finalRoute.getAnnotationMetadata().getValue(Produces.class, String.class).ifPresent(containerResponse::contentType);
        }
        finalRoute.getAnnotationMetadata().getValue(Status.class, HttpStatus.class).ifPresent(httpStatus -> containerResponse.status(httpStatus));
    }

    private void handlePossibleErrorStatus(
        MicronautAwsProxyRequest<AwsProxyRequest, ?> request,
        MicronautAwsProxyResponse<?> response) {

        final MediaType contentType = request.getContentType().orElse(null);
        final String requestMethodName = request.getMethodName();

        // if there is no route present try to locate a route that matches a different HTTP method
        final List<UriRouteMatch<?, ?>> anyMatchingRoutes = router
            .findAny(request.getPath(), request)
            .collect(Collectors.toList());
        final Collection<MediaType> acceptedTypes = request.accept();
        final boolean hasAcceptHeader = CollectionUtils.isNotEmpty(acceptedTypes);

        Set<MediaType> acceptableContentTypes = contentType != null ? new HashSet<>(5) : null;
        Set<String> allowedMethods = new HashSet<>(5);
        Set<MediaType> produceableContentTypes = hasAcceptHeader ? new HashSet<>(5) : null;
        for (UriRouteMatch<?, ?> anyRoute : anyMatchingRoutes) {
            final String routeMethod = anyRoute.getRoute().getHttpMethodName();
            if (!requestMethodName.equals(routeMethod)) {
                allowedMethods.add(routeMethod);
            }
            if (contentType != null && !anyRoute.doesConsume(contentType)) {
                acceptableContentTypes.addAll(anyRoute.getRoute().getConsumes());
            }
            if (hasAcceptHeader && !anyRoute.doesProduce(acceptedTypes)) {
                produceableContentTypes.addAll(anyRoute.getRoute().getProduces());
            }
        }

        if (CollectionUtils.isNotEmpty(acceptableContentTypes)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Content type not allowed for URI {}, method {}, and content type {}", request.getUri(),
                    requestMethodName, contentType);
            }

            handleStatusError(
                request,
                response,
                HttpResponse.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE),
                "Content Type [" + contentType + "] not allowed. Allowed types: " + acceptableContentTypes);
            return;
        }

        if (CollectionUtils.isNotEmpty(produceableContentTypes)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Content type not allowed for URI {}, method {}, and content type {}", request.getUri(),
                    requestMethodName, contentType);
            }

            handleStatusError(
                request,
                response,
                HttpResponse.status(HttpStatus.NOT_ACCEPTABLE),
                "Specified Accept Types " + acceptedTypes + " not supported. Supported types: " + produceableContentTypes);
            return;
        }

        if (!allowedMethods.isEmpty()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Method not allowed for URI {} and method {}", request.getUri(), requestMethodName);
            }

            handleStatusError(
                request,
                response,
                HttpResponse.notAllowedGeneric(allowedMethods),
                "Method [" + requestMethodName + "] not allowed for URI [" + request.getUri() + "]. Allowed methods: " + allowedMethods);
            return;
        }

        handleStatusError(
            request,
            response,
            HttpResponse.notFound(),
            "Page Not Found");
    }

    private void handleStatusError(
        MicronautAwsProxyRequest<AwsProxyRequest, ?> request,
        MicronautAwsProxyResponse<?> response,
        MutableHttpResponse<?> defaultResponse,
        String message) {

        Optional<RouteMatch<Object>> statusRoute = router.findStatusRoute(defaultResponse.status(), request);
        if (statusRoute.isPresent()) {
            handleRouteMatch(statusRoute.get(), request, response);
        } else {
            if (request.getMethod() != HttpMethod.HEAD) {
                defaultResponse = errorResponseProcessor.processResponse(
                    ErrorContext.builder(request).errorMessage(message).build(),
                    defaultResponse
                );
                if (!defaultResponse.getContentType().isPresent()) {
                    defaultResponse = defaultResponse.contentType(MediaType.APPLICATION_JSON_TYPE);
                }
            }

            filterAndEncodeResponse(request, response, Publishers.just(defaultResponse));
        }
    }

    private void filterAndEncodeResponse(
        MicronautAwsProxyRequest<AwsProxyRequest, ?> request,
        MicronautAwsProxyResponse<?> response,
        Publisher<MutableHttpResponse<?>> responsePublisher) {
        AtomicReference<HttpRequest<?>> requestReference = new AtomicReference<>(request);

        Flux.from(routeExecutor.filterPublisher(requestReference, responsePublisher))
            .contextWrite(ctx -> ctx.put(ServerRequestContext.KEY, request))
            .subscribe(new Subscriber<MutableHttpResponse<?>>() {
                Subscription subscription;

                @Override
                public void onSubscribe(Subscription s) {
                    this.subscription = s;
                    s.request(1);
                }

                @Override
                public void onNext(MutableHttpResponse<?> message) {
                    toAwsProxyResponse(response, message);
                    subscription.request(1);
                }

                @Override
                public void onError(Throwable t) {
                    try {
                        final MutableHttpResponse<?> defaultErrorResponse = routeExecutor.createDefaultErrorResponse(request, t);
                        toAwsProxyResponse(response, defaultErrorResponse);
                    } finally {
                        response.close();
                    }
                }

                @Override
                public void onComplete() {
                    response.close();
                }
            });
    }

    @Override
    public void close() {
        this.applicationContext.close();
    }

}
