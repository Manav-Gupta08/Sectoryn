#include "app/Application.hpp"

#include <exception>
#include <iostream>

int main(int argc, char* argv[]) {
    try {
        sectoryn::Application app(argc, argv);
        return app.run();
    } catch (const std::exception& e) {
        std::cerr << "Sectoryn terminated: " << e.what() << '\n';
    } catch (...) {
        std::cerr << "Sectoryn terminated: unknown exception\n";
    }
    return 1;
}
