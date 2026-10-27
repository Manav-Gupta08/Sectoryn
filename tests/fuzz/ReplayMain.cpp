#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>

// Provided by each harness.
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size);

// Runs every file given on the command line through the harness once.
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "usage: " << argv[0] << " input...\n";
        return 2;
    }
    for (int i = 1; i < argc; ++i) {
        std::ifstream in(argv[i], std::ios::binary);
        if (!in) {
            std::cerr << "cannot read " << argv[i] << '\n';
            return 1;
        }
        const std::vector<char> bytes{std::istreambuf_iterator<char>(in),
                                      std::istreambuf_iterator<char>()};
        LLVMFuzzerTestOneInput(reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size());
        std::cout << argv[i] << ": ok\n";
    }
    return 0;
}
