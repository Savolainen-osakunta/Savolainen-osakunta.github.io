# Savolaisen osakunnan nettisivut – Github pages edition

See live at http://savolainen-osakunta.github.io.

## How to test locally

Easy way (atm).

1. [Install nix](https://nixos.org/download.html) (Skip if you already have it)
2. `git clone git@github.com:Savolainen-osakunta/Savolainen-osakunta.github.io.git`
3. Run `nix-shell` in repository.
4. Open <http://127.0.0.1:4000>

Alternatively:

1. Install gem & bundler (eg. sudo gem install bundler)
2. `bundle install --path vendor/bundle`
3. `bundle exec jekyll serve`
4. Open <http://127.0.0.1:4000>

## Contributing

Add/modify content under the `_pages` directory.
