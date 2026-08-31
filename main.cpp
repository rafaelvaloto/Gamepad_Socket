#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#endif
#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>
#ifdef _WIN32
#include <ViGEm/Client.h>
#endif

namespace
{
	struct InputState;
	void parse(std::string line, InputState& state);
	void logInfo(const std::string& message)
	{
		std::cout << "[INFO] " << message << std::endl;
	}

	void logError(const std::string& message)
	{
		std::cerr << "[ERROR] " << message << std::endl;
	}

#ifdef _WIN32
	std::string vigemError(VIGEM_ERROR error)
	{
		std::ostringstream stream;
		stream << "0x" << std::uppercase << std::hex << static_cast<unsigned long>(error);
		return stream.str();
	}
#endif

	struct InputState
	{
		bool cross{}, circle{}, square{}, triangle{}, up{}, down{}, left{}, right{}, start{}, share{}, ps{};
		bool lb{}, rb{}, ls{}, rs{};
		float lt{}, rt{}, lx{}, ly{}, rx{}, ry{};
	};
	float value(std::string s)
	{
		std::replace(s.begin(), s.end(), ',', '.');
		return std::clamp(std::strtof(s.c_str(), nullptr), -1.0f, 1.0f);
	}
	bool pressed(std::string s)
	{
		for (char& c : s)
		{
			c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
		}
		return s == "1" || s == "true" || s == "on" || s == "down";
	}
	uint32_t rotateLeft(uint32_t value, int count)
	{
		return (value << count) | (value >> (32 - count));
	}
	std::array<unsigned char, 20> sha1(const std::string& input)
	{
		std::vector<unsigned char> data(input.begin(), input.end());
		const uint64_t bitLength = static_cast<uint64_t>(data.size()) * 8;
		data.push_back(0x80);
		while ((data.size() % 64) != 56)
		{
			data.push_back(0);
		}
		for (int i = 7; i >= 0; --i)
		{
			data.push_back(static_cast<unsigned char>(bitLength >> (i * 8)));
		}
		uint32_t h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;
		for (size_t offset = 0; offset < data.size(); offset += 64)
		{
			std::array<uint32_t, 80> words{};
			for (int i = 0; i < 16; ++i)
			{
				words[i] = (data[offset + i * 4] << 24) | (data[offset + i * 4 + 1] << 16) | (data[offset + i * 4 + 2] << 8) | data[offset + i * 4 + 3];
			}
			for (int i = 16; i < 80; ++i)
			{
				words[i] = rotateLeft(words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16], 1);
			}
			uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;
			for (int i = 0; i < 80; ++i)
			{
				uint32_t f, k;
				if (i < 20)
				{
					f = (b & c) | ((~b) & d);
					k = 0x5A827999;
				}
				else if (i < 40)
				{
					f = b ^ c ^ d;
					k = 0x6ED9EBA1;
				}
				else if (i < 60)
				{
					f = (b & c) | (b & d) | (c & d);
					k = 0x8F1BBCDC;
				}
				else
				{
					f = b ^ c ^ d;
					k = 0xCA62C1D6;
				}
				const uint32_t temp = rotateLeft(a, 5) + f + e + k + words[i];
				e = d;
				d = c;
				c = rotateLeft(b, 30);
				b = a;
				a = temp;
			}
			h0 += a;
			h1 += b;
			h2 += c;
			h3 += d;
			h4 += e;
		}
		std::array<unsigned char, 20> result{};
		const uint32_t hashes[] = {h0, h1, h2, h3, h4};
		for (int i = 0; i < 5; ++i)
		{
			for (int j = 0; j < 4; ++j)
			{
				result[i * 4 + j] = static_cast<unsigned char>(hashes[i] >> (24 - j * 8));
			}
		}
		return result;
	}
	std::string base64(const std::array<unsigned char, 20>& data)
	{
		static constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
		std::string result;
		int bits = 0, buffer = 0;
		for (unsigned char byte : data)
		{
			buffer = (buffer << 8) | byte;
			bits += 8;
			while (bits >= 6)
			{
				bits -= 6;
				result += alphabet[(buffer >> bits) & 0x3F];
			}
		}
		if (bits > 0)
		{
			result += alphabet[(buffer << (6 - bits)) & 0x3F];
		}
		while (result.size() % 4)
		{
			result += '=';
		}
		return result;
	}
	bool sendAll(SOCKET socket, const std::string& data)
	{
		size_t sent = 0;
		while (sent < data.size())
		{
			const int count = send(socket, data.data() + sent, static_cast<int>(data.size() - sent), 0);
			if (count <= 0)
			{
				return false;
			}
			sent += count;
		}
		return true;
	}
	bool completeWebSocketHandshake(SOCKET client, const std::string& headers)
	{
		const std::string name = "Sec-WebSocket-Key:";
		const size_t start = headers.find(name);
		if (start == std::string::npos)
		{
			return false;
		}
		const size_t keyStart = headers.find_first_not_of(" \t", start + name.size());
		const size_t keyEnd = headers.find("\r\n", keyStart);
		if (keyStart == std::string::npos || keyEnd == std::string::npos)
		{
			return false;
		}
		const std::string accept = base64(sha1(headers.substr(keyStart, keyEnd - keyStart) + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"));
		return sendAll(client, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n");
	}
	bool processWebSocketFrames(SOCKET client, std::string& buffer, std::string& message, InputState& state)
	{
		while (buffer.size() >= 2)
		{
			const unsigned char first = static_cast<unsigned char>(buffer[0]);
			const unsigned char second = static_cast<unsigned char>(buffer[1]);
			const bool finalFrame = (first & 0x80) != 0;
			const unsigned char opcode = first & 0x0F;
			const bool masked = (second & 0x80) != 0;
			uint64_t length = second & 0x7F;
			size_t headerSize = 2;
			if (!masked)
			{
				logError("WebSocket client sent an unmasked frame.");
				return false;
			}
			if (length == 126)
			{
				if (buffer.size() < 4)
				{
					return true;
				}
				length = (static_cast<unsigned char>(buffer[2]) << 8) | static_cast<unsigned char>(buffer[3]);
				headerSize = 4;
			}
			else if (length == 127)
			{
				if (buffer.size() < 10)
				{
					return true;
				}
				length = 0;
				for (int i = 0; i < 8; ++i)
				{
					length = (length << 8) | static_cast<unsigned char>(buffer[2 + i]);
				}
				headerSize = 10;
			}
			if (length > 16 * 1024 * 1024 || buffer.size() < headerSize + 4 + length)
			{
				return length > 16 * 1024 * 1024 ? false : true;
			}
			const size_t maskOffset = headerSize;
			const size_t payloadOffset = headerSize + 4;
			std::string payload(buffer, payloadOffset, static_cast<size_t>(length));
			for (size_t i = 0; i < payload.size(); ++i)
			{
				payload[i] ^= buffer[maskOffset + i % 4];
			}
			buffer.erase(0, payloadOffset + static_cast<size_t>(length));
			if (opcode == 0x8)
			{
				sendAll(client, "\x88\x00");
				return false;
			}
			if (opcode == 0x9)
			{
				const std::string pong = std::string("\x8A", 1) + static_cast<char>(payload.size()) + payload;
				if (!sendAll(client, pong))
				{
					return false;
				}
				continue;
			}
			if (opcode == 0x1 || opcode == 0x0)
			{
				message += payload;
				if (finalFrame)
				{
					size_t end;
					while ((end = message.find('\n')) != std::string::npos)
					{
						parse(message.substr(0, end), state);
						message.erase(0, end + 1);
					}
					if (!message.empty())
					{
						parse(message, state);
						message.clear();
					}
				}
			}
		}
		return true;
	}
	void parse(std::string line, InputState& s)
	{
		if (!line.empty() && line.back() == '\r')
		{
			line.pop_back();
		}
		if (line.empty())
		{
			return;
		}
		std::istringstream in(line);
		std::string part;
		while (in >> part)
		{
			auto p = part.find('=');
			if (p == std::string::npos)
			{
				if (part == "clear" || part == "reset")
				{
					s = {};
				}
				continue;
			}
			std::string key = part.substr(0, p), val = part.substr(p + 1);
			for (char& c : key)
			{
				c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
			}
			const std::unordered_map<std::string, bool*> buttons{{"cross", &s.cross}, {"a", &s.cross}, {"circle", &s.circle}, {"b", &s.circle}, {"square", &s.square}, {"x", &s.square}, {"triangle", &s.triangle}, {"y", &s.triangle}, {"up", &s.up}, {"dpadup", &s.up}, {"down", &s.down}, {"dpaddown", &s.down}, {"left", &s.left}, {"dpadleft", &s.left}, {"right", &s.right}, {"dpadright", &s.right}, {"start", &s.start}, {"options", &s.start}, {"share", &s.share}, {"back", &s.share}, {"ps", &s.ps}, {"lb", &s.lb}, {"l1", &s.lb}, {"rb", &s.rb}, {"r1", &s.rb}, {"ls", &s.ls}, {"l3", &s.ls}, {"rs", &s.rs}, {"r3", &s.rs}};
			if (auto it = buttons.find(key); it != buttons.end())
			{
				*it->second = pressed(val);
			}
			else if (key == "lx")
			{
				s.lx = value(val);
			}
			else if (key == "ly")
			{
				s.ly = value(val);
			}
			else if (key == "rx")
			{
				s.rx = value(val);
			}
			else if (key == "ry")
			{
				s.ry = value(val);
			}
			else if (key == "lt" || key == "lefttrigger")
			{
				s.lt = std::clamp(value(val), 0.0f, 1.0f);
			}
			else if (key == "rt" || key == "righttrigger")
			{
				s.rt = std::clamp(value(val), 0.0f, 1.0f);
			}
			// Unknown input fields are ignored to keep the protocol forward-compatible.
		}
	}
#ifdef _WIN32
	class ViGEmGamepad
	{
	public:
		explicit ViGEmGamepad(bool ds4)
		    : ds4_(ds4)
		{}
		~ViGEmGamepad() { shutdown(); }
		bool init()
		{
			client_ = vigem_alloc();
			if (!client_)
			{
				logError("ViGEm client allocation failed.");
				return false;
			}
			const VIGEM_ERROR connectError = vigem_connect(client_);
			if (!VIGEM_SUCCESS(connectError))
			{
				logError("Failed to connect to the ViGEm bus (error " + vigemError(connectError) + "). Is ViGEmBus installed?");
				return false;
			}
			logInfo("Connected to the ViGEm bus.");
			target_ = ds4_ ? vigem_target_ds4_alloc() : vigem_target_x360_alloc();
			if (!target_)
			{
				logError("Failed to allocate the virtual gamepad target.");
				return false;
			}
			const VIGEM_ERROR addError = vigem_target_add(client_, target_);
			if (!VIGEM_SUCCESS(addError))
			{
				logError("Failed to add the virtual gamepad target (error " + vigemError(addError) + ").");
				return false;
			}
			logInfo(std::string("Virtual ") + (ds4_ ? "DualShock 4" : "Xbox 360") + " controller connected.");
			return true;
		}
		void update(const InputState& s)
		{
			if (!client_ || !target_) return;

			if (ds4_)
			{
				DS4_REPORT report;
				DS4_REPORT_INIT(&report);
				report.wButtons |= s.cross ? DS4_BUTTON_CROSS : 0;
				report.wButtons |= s.circle ? DS4_BUTTON_CIRCLE : 0;
				report.wButtons |= s.square ? DS4_BUTTON_SQUARE : 0;
				report.wButtons |= s.triangle ? DS4_BUTTON_TRIANGLE : 0;
				report.wButtons |= s.start ? DS4_BUTTON_OPTIONS : 0;
				report.wButtons |= s.share ? DS4_BUTTON_SHARE : 0;
				report.wButtons |= s.lb ? DS4_BUTTON_SHOULDER_LEFT : 0;
				report.wButtons |= s.rb ? DS4_BUTTON_SHOULDER_RIGHT : 0;
				report.wButtons |= s.ls ? DS4_BUTTON_THUMB_LEFT : 0;
				report.wButtons |= s.rs ? DS4_BUTTON_THUMB_RIGHT : 0;
				if (s.up && s.right) DS4_SET_DPAD(&report, DS4_BUTTON_DPAD_NORTHEAST);
				else if (s.up && s.left) DS4_SET_DPAD(&report, DS4_BUTTON_DPAD_NORTHWEST);
				else if (s.down && s.right) DS4_SET_DPAD(&report, DS4_BUTTON_DPAD_SOUTHEAST);
				else if (s.down && s.left) DS4_SET_DPAD(&report, DS4_BUTTON_DPAD_SOUTHWEST);
				else if (s.up) DS4_SET_DPAD(&report, DS4_BUTTON_DPAD_NORTH);
				else if (s.right) DS4_SET_DPAD(&report, DS4_BUTTON_DPAD_EAST);
				else if (s.down) DS4_SET_DPAD(&report, DS4_BUTTON_DPAD_SOUTH);
				else if (s.left) DS4_SET_DPAD(&report, DS4_BUTTON_DPAD_WEST);
				report.bSpecial = s.ps ? DS4_SPECIAL_BUTTON_PS : 0;
				report.bThumbLX = axis8(s.lx);
				report.bThumbLY = axis8(-s.ly);
				report.bThumbRX = axis8(s.rx);
				report.bThumbRY = axis8(-s.ry);
				report.bTriggerL = trig(s.lt);
				report.bTriggerR = trig(s.rt);

				const VIGEM_ERROR error = vigem_target_ds4_update(client_, target_, report);
				if (!VIGEM_SUCCESS(error))
				{
					logError("Failed to update the DS4 report (error " + vigemError(error) + ").");
				}
				return;
			}

			XUSB_REPORT report;
			XUSB_REPORT_INIT(&report);

			if (s.cross) report.wButtons |= XUSB_GAMEPAD_A;
			if (s.circle) report.wButtons |= XUSB_GAMEPAD_B;
			if (s.square) report.wButtons |= XUSB_GAMEPAD_X;
			if (s.triangle) report.wButtons |= XUSB_GAMEPAD_Y;

			if (s.up) report.wButtons |= XUSB_GAMEPAD_DPAD_UP;
			if (s.down) report.wButtons |= XUSB_GAMEPAD_DPAD_DOWN;
			if (s.left) report.wButtons |= XUSB_GAMEPAD_DPAD_LEFT;
			if (s.right) report.wButtons |= XUSB_GAMEPAD_DPAD_RIGHT;

			if (s.start) report.wButtons |= XUSB_GAMEPAD_START;
			if (s.share) report.wButtons |= XUSB_GAMEPAD_BACK;

			if (s.lb) report.wButtons |= XUSB_GAMEPAD_LEFT_SHOULDER;
			if (s.rb) report.wButtons |= XUSB_GAMEPAD_RIGHT_SHOULDER;

			if (s.ls) report.wButtons |= XUSB_GAMEPAD_LEFT_THUMB;
			if (s.rs) report.wButtons |= XUSB_GAMEPAD_RIGHT_THUMB;

			if (s.ps) report.wButtons |= XUSB_GAMEPAD_GUIDE;

			report.bLeftTrigger = trig(s.lt);
			report.bRightTrigger = trig(s.rt);

			report.sThumbLX = axis16(s.lx);
			report.sThumbLY = axis16(s.ly);
			report.sThumbRX = axis16(s.rx);
			report.sThumbRY = axis16(s.ry);

			const VIGEM_ERROR error = vigem_target_x360_update(client_, target_, report);
			if (!VIGEM_SUCCESS(error))
			{
				logError("Failed to update the Xbox report (error " + vigemError(error) + ").");
			}
		}

	private:
		static BYTE axis8(float v) { return static_cast<BYTE>(std::clamp((v + 1.0f) * 127.5f, 0.0f, 255.0f)); }
		static SHORT axis16(float v) { return static_cast<SHORT>(std::clamp(v * 32767.0f, -32768.0f, 32767.0f)); }
		static BYTE trig(float v) { return static_cast<BYTE>(std::clamp(v, 0.0f, 1.0f) * 255.0f); }
		void shutdown()
		{
			if (target_)
			{
				const VIGEM_ERROR error = vigem_target_remove(client_, target_);
				if (!VIGEM_SUCCESS(error))
				{
					logError("Failed to remove the virtual gamepad target (error " + vigemError(error) + ").");
				}
				vigem_target_free(target_);
				target_ = nullptr;
			}
			if (client_)
			{
				vigem_disconnect(client_);
				vigem_free(client_);
				client_ = nullptr;
				logInfo("Disconnected from the ViGEm bus.");
			}
		}
		bool ds4_{};
		PVIGEM_CLIENT client_{};
		PVIGEM_TARGET target_{};
	};
#endif
} // namespace
int main(int argc, char** argv)
{
#ifndef _WIN32
	logError("This server requires Windows, WinSock, and ViGEm.");
	return 1;
#else
	std::string controller = "xbox";
	unsigned short port = 26760;
	for (int i = 1; i < argc; ++i)
	{
		std::string a = argv[i];
		if (a == "--controller" && i + 1 < argc)
		{
			controller = argv[++i];
		}
		else if (a == "--port" && i + 1 < argc)
		{
			port = static_cast<unsigned short>(std::stoi(argv[++i]));
		}
		else if (a == "--help")
		{
			std::cout << "Usage: Gamepad_Socket [--controller xbox|ds4] [--port 26760]\n";
			return 0;
		}
	}
	if (controller != "xbox" && controller != "ds4")
	{
		logError("Controller must be xbox or ds4.");
		return 2;
	}
	ViGEmGamepad gamepad(controller == "ds4");
	if (!gamepad.init())
	{
		logError("Failed to initialize ViGEm.");
		return 3;
	}
	WSADATA wsa{};
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		logError("WinSock initialization failed (error " + std::to_string(WSAGetLastError()) + ").");
		return 4;
	}
	SOCKET server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	sockaddr_in addr{};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	if (server == INVALID_SOCKET || bind(server, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR || listen(server, 1) == SOCKET_ERROR)
	{
		logError("Failed to open TCP port " + std::to_string(port) + " (error " + std::to_string(WSAGetLastError()) + ").");
		if (server != INVALID_SOCKET)
		{
			closesocket(server);
		}
		WSACleanup();
		return 5;
	}
	logInfo("Listening for WebSocket connections on port " + std::to_string(port) + " as " + controller + ".");
	for (;;)
	{
		SOCKET client = accept(server, nullptr, nullptr);
		if (client == INVALID_SOCKET)
		{
			logError("Failed to accept a client connection (error " + std::to_string(WSAGetLastError()) + ").");
			break;
		}
		logInfo("Client connected.");
		InputState state{};
		std::string buffer;
		char chunk[4096];
		int n;
		bool handshakeComplete = false;
		std::string fragmentedMessage;
		while ((n = recv(client, chunk, sizeof(chunk), 0)) > 0)
		{
			buffer.append(chunk, n);
			if (!handshakeComplete)
			{
				const size_t headersEnd = buffer.find("\r\n\r\n");
				if (headersEnd == std::string::npos)
				{
					continue;
				}
				const std::string headers = buffer.substr(0, headersEnd + 4);
				if (!completeWebSocketHandshake(client, headers))
				{
					logError("Invalid WebSocket handshake.");
					break;
				}
				buffer.erase(0, headersEnd + 4);
				handshakeComplete = true;
				logInfo("WebSocket connection established.");
			}
			if (!processWebSocketFrames(client, buffer, fragmentedMessage, state))
			{
				break;
			}
			gamepad.update(state);
		}
		closesocket(client);
		logInfo("Client disconnected.");
	}
	closesocket(server);
	WSACleanup();
	logInfo("Server stopped.");
	return 0;
#endif
}
