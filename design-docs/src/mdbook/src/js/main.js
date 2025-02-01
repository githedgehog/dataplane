figureBlockquoteToCaption = () => {
	const figures = document.querySelectorAll('figure');
	figures.forEach((figure, i) => {
		if (!figure.title) {
			console.warn("No title for figure!", figure);
			figure.title = `untitled-fig ${i + 1}`;
		}
		figure.setAttribute('aria-label', figure.title);
	});
	figures.forEach((figure, _i) => {
		if (!figure.id) {
				figure.id = `figure/${figure.title.replace(/\s/g, '-').toLowerCase()}`;
		}
	});
	figures.forEach(figure => {
		const blockquote = figure.querySelector('blockquote:last-child');
		if (!blockquote) {
			console.warn("No caption for figure!", figure);
			return;
		}
		const caption = document.createElement('figcaption');
		const captionAnchor = document.createElement('a');
		captionAnchor.setAttribute('href', `#figure/${figure.id}`);
		captionAnchor.classList.add('header');
		const figureLabel = document.createElement('a');
		figureLabel.href = `#${figure.id}`;
		figureLabel.classList.add('figure-label');
		figureLabel.innerText = figure.getAttribute('aria-label');
		figure.prepend(figureLabel);
		caption.append(captionAnchor);
		caption.append(...blockquote.childNodes);
		figure.append(caption);
		blockquote.remove();
	});
};

const embedPlantuml = async () => {
	const svgImages = document.querySelectorAll('img[src$=".svg"][src*="mdbook-plantuml"]');
	for (const svgImg of svgImages) {
		const svgWrapper = document.createElement('div');
		svgWrapper.setAttribute('class', 'svg-wrapper');
		svgWrapper.innerHTML = await (await fetch(svgImg.getAttribute('src'))).text();
		const svg = svgWrapper.querySelector('svg');
		if (!svg) {
			console.warn("No svg in wrapper: ", svgWrapper);
			continue;
		}
		const width = svg.getAttribute('width');
		const height = svg.getAttribute('height');
		if (width) {
			svg.removeAttribute('width');
			svg.style.maxWidth = width;
		}
		if (height) {
			svg.removeAttribute('height');
			svg.style.maxHeight = height;
		}
		svgImg.replaceWith(svgWrapper);
	}
}

const smarterSvgBackground = (svg) => {
	const style = window.getComputedStyle(svg);
	if (style.backgroundColor !== 'rgba(0, 0, 0, 0)') {
		return;
	}
	svg.style.backgroundColor = 'white';
}

const fixPlantumlSvgBackground = () => {
	const plantumlSvgs = document.querySelectorAll('div.svg-wrapper > svg');
	plantumlSvgs.forEach(smarterSvgBackground);
};

const main = async () => {
	await embedPlantuml();
	figureBlockquoteToCaption();
	fixPlantumlSvgBackground();
}

main().catch(console.error);
