#include "api_jai_gcaptcha.h"

using namespace api::jai;

void gcaptcha::verifyCaptcha(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback)
{
    LOG_TRACE << "(START) verifyCaptcha\n";

    Json::Value requestJson = *req->getJsonObject();
    Json::Value responseJson;

    if (!requestJson.isMember("token"))
    {
        responseJson["requestId"] = std::string("REQUEST") + std::to_string(std::time(0));
        responseJson["message"] = "Missing information.";
        responseJson["status"] = HttpStatusCode::k400BadRequest;
        responseJson["timestamp"] = std::to_string(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());

    }

    HttpClientPtr pHttpClient = drogon::HttpClient::newHttpClient(app().getCustomConfig()["gcaptcha"]["url"].asString());
    HttpRequestPtr _request = HttpRequest::newHttpRequest();
    _request->setMethod(drogon::Post);
    pHttpClient->setSockOptCallback([](int fd)
    {
        LOG_INFO << "setSockOptCallback:" << fd << '\n';
#if defined __APPLE__
        int optval = 10;
        ::setsockopt(fd,
            SOL_SOCKET,
            SO_KEEPALIVE,
            &optval,
            static_cast<socklen_t>(sizeof optval));
        ::setsockopt(fd,
            IPPROTO_TCP,
            TCP_KEEPALIVE,
            &optval,
            static_cast<socklen_t>(sizeof optval));
        ::setsockopt(fd,
            IPPROTO_TCP,
            TCP_KEEPINTVL,
            &optval,
            static_cast<socklen_t>(sizeof optval));
#elif defined __FreeBSD__
        int optval = 10;
        ::setsockopt(fd,
            IPPROTO_TCP,
            TCP_KEEPCNT,
            &optval,
            static_cast<socklen_t>(sizeof optval));
        ::setsockopt(fd,
            IPPROTO_TCP,
            TCP_KEEPIDLE,
            &optval,
            static_cast<socklen_t>(sizeof optval));
        ::setsockopt(fd,
            IPPROTO_TCP,
            TCP_KEEPINTVL,
            &optval,
            static_cast<socklen_t>(sizeof optval));
#elif defined __linux__
        int optval = 10;
        ::setsockopt(fd,
            SOL_TCP,
            TCP_KEEPCNT,
            &optval,
            static_cast<socklen_t>(sizeof optval));
        ::setsockopt(fd,
            SOL_TCP,
            TCP_KEEPIDLE,
            &optval,
            static_cast<socklen_t>(sizeof optval));
        ::setsockopt(fd,
            SOL_TCP,
            TCP_KEEPINTVL,
            &optval,
            static_cast<socklen_t>(sizeof optval));
#endif
    });
    _request->setPath(app().getCustomConfig()["gcaptcha"]["path"].asString());
    _request->setParameter("secret", app().getCustomConfig()["gcaptcha"]["secret"].asString());
    _request->setParameter("response", requestJson["token"].asString());
    _request->setParameter("remoteip", app().getCustomConfig()["gcaptcha"]["hostname"].asString());

    pHttpClient->sendRequest(_request,
        [=,&responseJson](ReqResult result, const HttpResponsePtr &response) 
        {
            switch (result)
            {
                case ReqResult::Ok:
                {
                    responseJson = *response->getJsonObject();
                    responseJson["requestId"] = std::string("REQUEST") + std::to_string(std::time(0));
                    responseJson["message"] = "Request sent successfully";
                    responseJson["status"] = HttpStatusCode::k200OK;
                    responseJson["timestamp"] = std::to_string(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
                }
                break;
                case ReqResult::BadResponse:
                {
                    responseJson["requestId"] = std::string("REQUEST") + std::to_string(std::time(0));
                    responseJson["message"] = to_string_view(result).data();
                    responseJson["status"] = HttpStatusCode::k400BadRequest;
                    responseJson["timestamp"] = std::to_string(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
                }
                break;
                case ReqResult::NetworkFailure:
                case ReqResult::BadServerAddress:
                case ReqResult::Timeout:
                case ReqResult::HandshakeError:
                case ReqResult::InvalidCertificate:
                case ReqResult::EncryptionFailure:
                {
                    responseJson["requestId"] = std::string("REQUEST") + std::to_string(std::time(0));
                    responseJson["message"] = to_string_view(result).data();
                    responseJson["status"] = HttpStatusCode::k500InternalServerError;
                    responseJson["timestamp"] = std::to_string(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
                }
                break;
            }
        });


    LOG_TRACE << "(END) verifyCaptcha\n";
    callback(HttpResponse::newHttpJsonResponse(responseJson));
}
