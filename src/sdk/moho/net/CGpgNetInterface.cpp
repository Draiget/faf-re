#include "CGpgNetInterface.h"

#include "moho/app/CWaitHandleSet.h"
using namespace moho;

CGpgNetInterface::CGpgNetInterface() :
	enable_shared_from_this(),
	mState(0),
	mServer(nullptr),
	mSocket(nullptr),
	mCommands(),
	mNATHandlerThread(nullptr),
	mLObj(),
	mNATHandler() {
	mEvent = CreateEventW(nullptr, 1, 0, nullptr);
	const auto handle = WIN_GetWaitHandleSet();
	handle->AddHandle(mEvent);
}

// 0x007B9070
void CGpgNetInterface::SetHandler(int port, boost::shared_ptr<INetNATTraversalHandler>* handler) {
}

// 0x007B9160
void CGpgNetInterface::ReceivePacket(u_long address, u_short port, const char* dat, size_t size) {
}

// 0x007BB250
int CGpgNetInterface::Execute() {
}

void CGpgNetInterface::ExpectedInt() noexcept(false) {
}

void CGpgNetInterface::ExpectedData() noexcept(false) {
}

void CGpgNetInterface::EnqueueCommand0(const char* str, int val) {
}

void CGpgNetInterface::Connect(u_long address, u_short port) {
}

void CGpgNetInterface::WriteCommand(const char* name, std::vector<SNetCommandArg>& args) {
}

void CGpgNetInterface::SendBottleneckCleared() {
}

void CGpgNetInterface::WriteCommand1(const char* name, SNetCommandArg* arg) {
}

void CGpgNetInterface::WriteCommand2(const char* name, SNetCommandArg* arg1, SNetCommandArg* arg2) {
}

void CGpgNetInterface::WriteCommand3(
	const char* name, 
	SNetCommandArg* arg1, 
	SNetCommandArg* arg2,
	SNetCommandArg* arg3)
{
}

void CGpgNetInterface::WriteCommand4(
	const char* name, 
	SNetCommandArg* arg1, 
	SNetCommandArg* arg2, 
	SNetCommandArg* arg3,
	SNetCommandArg* arg4)
{
}

void CGpgNetInterface::WriteCommandName(const char* name) {
}

void CGpgNetInterface::WriteString(const char* str) {
}

void CGpgNetInterface::WriteArg(SNetCommandArg* arg) {
}

void CGpgNetInterface::Process() {
}

void CGpgNetInterface::Test(std::vector<SNetCommandArg>& args) {
}

void CGpgNetInterface::Connected(std::vector<SNetCommandArg>& args) {
}

void CGpgNetInterface::CreateLobby(std::vector<SNetCommandArg>& args) {
}

void CGpgNetInterface::HostGame(std::vector<SNetCommandArg>& args) {
}

void CGpgNetInterface::JoinGame(std::vector<SNetCommandArg>& args) {
}

void CGpgNetInterface::ConnectToPeer(std::vector<SNetCommandArg>& args) {
}

void CGpgNetInterface::DisconnectFromPeer(std::vector<SNetCommandArg>& args) {
}

void CGpgNetInterface::HasSupCom(std::vector<SNetCommandArg>& args) {
}

void CGpgNetInterface::HasForgedAlliance(std::vector<SNetCommandArg>& args) {
}

void CGpgNetInterface::SendNatPacket(std::vector<SNetCommandArg>& args) {
}

void CGpgNetInterface::EjectPlayer(std::vector<SNetCommandArg>& args) {
}

void CGpgNetInterface::ConnectThread(u_long address, u_short port) {
}

void CGpgNetInterface::ReadFromSocket() {
}

void CGpgNetInterface::EnqueueCommand(const char* name, std::vector<SNetCommandArg>& args, int val) {
}
