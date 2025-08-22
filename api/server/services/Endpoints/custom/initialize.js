const {
  CacheKeys,
  ErrorTypes,
  envVarRegex,
  FetchTokenConfig,
  extractEnvVariable,
} = require('librechat-data-provider');
const { Providers } = require('@librechat/agents');
const { getOpenAIConfig, createHandleLLMNewToken, resolveHeaders } = require('@librechat/api');
const { getUserKeyValues, checkUserKeyExpiry } = require('~/server/services/UserService');
const { getCustomEndpointConfig } = require('~/server/services/Config');
const { fetchModels } = require('~/server/services/ModelService');
const OpenAIClient = require('~/app/clients/OpenAIClient');
const { isUserProvided } = require('~/server/utils');
const getLogStores = require('~/cache/getLogStores');

const tokenExchangeManager = require('../../tokenExchange');

const { PROXY } = process.env;

const initializeClient = async ({ req, res, endpointOption, optionsOnly, overrideEndpoint }) => {
  const { key: expiresAt } = req.body;
  const endpoint = overrideEndpoint ?? req.body.endpoint;
  
  console.info(`[initialize] Starting initialization for endpoint: ${endpoint}`);

  const endpointConfig = await getCustomEndpointConfig(endpoint);
  if (!endpointConfig) {
    throw new Error(`Config not found for the ${endpoint} custom endpoint.`);
  }

  const CUSTOM_API_KEY = extractEnvVariable(endpointConfig.apiKey);
  const CUSTOM_BASE_URL = extractEnvVariable(endpointConfig.baseURL);

  let resolvedHeaders = resolveHeaders(endpointConfig.headers, req.user);

  const userProvidesKey = isUserProvided(CUSTOM_API_KEY);
  const userProvidesURL = isUserProvided(CUSTOM_BASE_URL);

  let userValues = null;
  if (expiresAt && (userProvidesKey || userProvidesURL)) {
    checkUserKeyExpiry(expiresAt, endpoint);
    userValues = await getUserKeyValues({ userId: req.user.id, name: endpoint });
  }

  let apiKey = userProvidesKey ? userValues?.apiKey : CUSTOM_API_KEY;
  let baseURL = userProvidesURL ? userValues?.baseURL : CUSTOM_BASE_URL;

  // Try Token Exchange BEFORE validation checks
  if (process.env.ENABLE_TOKEN_EXCHANGE_FOR_CUSTOM === 'true' && tokenExchangeManager.isEnabled()) {
    console.debug('[initialize] Token Exchange enabled, checking if this is our API:', baseURL);
    const exchangedToken = await tokenExchangeManager.getApiTokenForRequest(req, apiKey, baseURL);
    if (exchangedToken && exchangedToken !== apiKey) {
      console.info('[initialize] Using OIDC token for our API endpoint');
      apiKey = exchangedToken;
    } else {
      console.debug('[initialize] Using default API key (no OIDC token or not our API)');
    }
  }

  // Now check if we have valid apiKey and baseURL after token exchange
  if (!apiKey || (CUSTOM_API_KEY.match(envVarRegex) && apiKey === CUSTOM_API_KEY)) {
    throw new Error(`Missing API Key for ${endpoint}.`);
  }

  if (!baseURL || CUSTOM_BASE_URL.match(envVarRegex)) {
    throw new Error(`Missing Base URL for ${endpoint}.`);
  }

  if (userProvidesKey & !apiKey) {
    throw new Error(
      JSON.stringify({
        type: ErrorTypes.NO_USER_KEY,
      }),
    );
  }

  if (userProvidesURL && !baseURL) {
    throw new Error(
      JSON.stringify({
        type: ErrorTypes.NO_BASE_URL,
      }),
    );
  }

  const cache = getLogStores(CacheKeys.TOKEN_CONFIG);
  const tokenKey =
    !endpointConfig.tokenConfig && (userProvidesKey || userProvidesURL)
      ? `${endpoint}:${req.user.id}`
      : endpoint;

  let endpointTokenConfig =
    !endpointConfig.tokenConfig &&
    FetchTokenConfig[endpoint.toLowerCase()] &&
    (await cache.get(tokenKey));

  if (
    FetchTokenConfig[endpoint.toLowerCase()] &&
    endpointConfig &&
    endpointConfig.models.fetch &&
    !endpointTokenConfig
  ) {
    await fetchModels({ apiKey, baseURL, name: endpoint, user: req.user.id, tokenKey });
    endpointTokenConfig = await cache.get(tokenKey);
  }

  const customOptions = {
    headers: resolvedHeaders,
    addParams: endpointConfig.addParams,
    dropParams: endpointConfig.dropParams,
    customParams: endpointConfig.customParams,
    titleConvo: endpointConfig.titleConvo,
    titleModel: endpointConfig.titleModel,
    forcePrompt: endpointConfig.forcePrompt,
    summaryModel: endpointConfig.summaryModel,
    modelDisplayLabel: endpointConfig.modelDisplayLabel,
    titleMethod: endpointConfig.titleMethod ?? 'completion',
    contextStrategy: endpointConfig.summarize ? 'summarize' : null,
    directEndpoint: endpointConfig.directEndpoint,
    titleMessageRole: endpointConfig.titleMessageRole,
    streamRate: endpointConfig.streamRate,
    endpointTokenConfig,
  };

  /** @type {undefined | TBaseEndpoint} */
  const allConfig = req.app.locals.all;
  if (allConfig) {
    customOptions.streamRate = allConfig.streamRate;
  }

  let clientOptions = {
    reverseProxyUrl: baseURL ?? null,
    proxy: PROXY ?? null,
    req,
    res,
    ...customOptions,
    ...endpointOption,
  };

  if (optionsOnly) {
    const modelOptions = endpointOption?.model_parameters ?? {};
    if (endpoint !== Providers.OLLAMA) {
      clientOptions = Object.assign(
        {
          modelOptions,
        },
        clientOptions,
      );
      clientOptions.modelOptions.user = req.user.id;
      const options = getOpenAIConfig(apiKey, clientOptions, endpoint);
      if (options != null) {
        options.useLegacyContent = true;
        options.endpointTokenConfig = endpointTokenConfig;
      }
      if (!clientOptions.streamRate) {
        return options;
      }
      options.llmConfig.callbacks = [
        {
          handleLLMNewToken: createHandleLLMNewToken(clientOptions.streamRate),
        },
      ];
      return options;
    }

    if (clientOptions.reverseProxyUrl) {
      modelOptions.baseUrl = clientOptions.reverseProxyUrl.split('/v1')[0];
      delete clientOptions.reverseProxyUrl;
    }

    return {
      useLegacyContent: true,
      llmConfig: modelOptions,
    };
  }

  const client = new OpenAIClient(apiKey, clientOptions);
  return {
    client,
    openAIApiKey: apiKey,
  };
};

module.exports = initializeClient;
