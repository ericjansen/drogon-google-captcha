#pragma once

#include <drogon/HttpController.h>
#include <drogon/HttpClient.h>
#if defined __FreeBSD__ || defined __APPLE__
#include <netinet/tcp.h>
#elif defined __linux__
#include <sys/socket.h>
#include <netinet/tcp.h>
#endif

using namespace drogon;

namespace api
{
namespace jai
{
class gcaptcha : public drogon::HttpController<gcaptcha>
{
  public:
    METHOD_LIST_BEGIN
    METHOD_ADD(gcaptcha::verifyCaptcha, "/verify", Post); // path is /api/jai/gcaptcha/{arg2}/{arg1}

    METHOD_LIST_END
    void verifyCaptcha(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback);
};
}
}
