const formatBlockcite = () => {
	const spannedCitations = document.querySelectorAll('cite[data-scope]')
	console.log("spannedCitations", spannedCitations);
	spannedCitations.forEach(spannedCitation => {
		const target = spannedCitation.getAttribute('data-scope');
		if (!target || target === '') {
			return;
		}
		const targetElement = document.getElementById(target);
		console.log("targetElement", targetElement);
		const contentDiv = document.createElement('div');
		contentDiv.setAttribute("class", "cited-content");
		const citationDiv = document.createElement('div');
		const citationBlock = document.createElement('div');
		citationBlock.setAttribute("class", "citation-block");
		citationDiv.append(citationBlock);
		citationDiv.setAttribute("class", "citation");
		contentDiv.append(...targetElement.childNodes);
		citationBlock.append(spannedCitation);
		targetElement.classList.add('blockcite');
		targetElement.append(contentDiv, citationDiv);

	});

};

const referencesSection = () => {
	const generatedReferences = document.querySelector('#refs');
	if (!generatedReferences) {
		return;
	}
	const section = document.createElement('section');
	section.setAttribute("class", "references");
	const title = document.createElement('h2');
	title.setAttribute("id", "references");
	const titleLink = document.createElement('a');
	titleLink.setAttribute("href", "#references");
	titleLink.classList.add('header');
	titleLink.innerText = "References";
	title.appendChild(titleLink);
	section.appendChild(title);
	section.appendChild(generatedReferences);
	const main = document.querySelector('main');
	main.appendChild(section);
};

const citationReferences = () => {
	const bibEntries = document.querySelectorAll('section.references div.csl-entry[id^="ref-"]');
	bibEntries.forEach(((bibEntry, _idx) => {
		const rInline = bibEntry.querySelector('span.csl-right-inline');
		const bibId = bibEntry.getAttribute('id');
		const query = `a[href="#${bibId}"]:not(.reference-anchor)`;
		document.querySelectorAll(query).forEach(((citationAnchor, idx) => {
			if (!citationAnchor.id) {
				citationAnchor.setAttribute("id", `citation/${bibEntry.getAttribute("id")}/${idx + 1}`);
				citationAnchor.classList.add(`citation`);
				citationAnchor.classList.add(`${bibEntry.getAttribute("id")}`);
			}
			const backReferenceLink = document.createElement('a');
			backReferenceLink.href = `#${citationAnchor.id}`;
			backReferenceLink.classList.add('back-reference-source');
			rInline.appendChild(backReferenceLink);
			citationAnchor.innerHTML = `<cite class="reference">${citationAnchor.innerHTML}</cite>`;
		}));
	}));

};

const transformIfText = (element, transform) => {
	if (element.nodeType === Node.ELEMENT_NODE) {
		element.childNodes.forEach(child => transformIfText(child, transform));
		return;
	}
	if (element.nodeType !== Node.TEXT_NODE) {
		return;
	}
	element.textContent = transform(element.textContent);
};

const _replaceInQuotes = (regex, replacement) => {
	const quotes = document.querySelectorAll('.quote');

	quotes.forEach(quote => {
		quote.childNodes.forEach(node => {
			transformIfText(node, text => text.replace(regex, replacement));
		})
	});
};

const replaceTrippleDashWithEmDashInBlockQuotes = () => _replaceInQuotes(/---/g, '—');

const formatBlockQuotes = () => {
	const quotes = document.querySelectorAll('.quote');
	quotes.forEach(quote => {
		// Trim leading whitespace from blockquotes (it gets added by the markdown parser)
		const blockQuotes = quote.querySelectorAll('blockquote');
		blockQuotes.forEach(blockQuote => {
			if (blockQuote.childNodes.length === 0) {
				return;
			}
			const firstChild = blockQuote.childNodes[0];
			if (firstChild.nodeType !== Node.TEXT_NODE) {
				return;
			}
			firstChild.textContent = firstChild.textContent.replace(/^\s+/, '');
		});
	});

	replaceTrippleDashWithEmDashInBlockQuotes();
};

const formatEquations = () => {
	const styleSheet = document.styleSheets[0];
	const equations = document.querySelectorAll('.katex-display');
	equations.forEach((equation) => {
		const container = document.createElement('div');
		container.classList.add('equation');
		container.innerHTML = equation.outerHTML;
		equation.replaceWith(container);
	});
	const equationLabels = document.querySelectorAll('.base .equation-label > span[id]');
	equationLabels.forEach((equationLabel, idx) => {
		const id = equationLabel.getAttribute('id');
		if (!id || id === '') {
			console.warn("Equation label missing id: ", equationLabel);
			return;
		}
		const equationNumber = document.createElement('a');

		const base = document.querySelector(`.equation:has(.equation-label > span[id="${id}"])`);
		if (!base) {
			console.warn(`No base for equation label: ${id}`);
			return;
		}
		const equationColumn = base.querySelector('.equation-column') ?? (() => {
			const eqnColumn = document.createElement('div');
			eqnColumn.classList.add('equation-column');
			base.append(eqnColumn);
			return eqnColumn
		})();
		if (!base) {
			console.warn("No base for equation label: ", equationLabel);
			return;
		}
		console.log("base", base);

		equationNumber.classList.add('equation-number');
		equationNumber.innerText = `(${idx + 1})`;
		equationNumber.setAttribute('id', `eq/${equationLabel.id}`);
		equationNumber.setAttribute('href', `#eq/${equationLabel.id}`);
		equationNumber.setAttribute('data-equation-number', `${idx + 1}`);
		equationColumn.append(equationNumber);

		const offset = {
			top: equationLabel.getBoundingClientRect().top - equationNumber.getBoundingClientRect().top,
		};
		const scroll = base.getBoundingClientRect().height + offset.top * 2;
		const equationNumberHeight = equationNumber.getBoundingClientRect().height;
		styleSheet.insertRule(`[id="${equationNumber.id}"] { position: relative; top: ${offset.top}px; left: 0; }`);
		styleSheet.insertRule(`[id="${equationNumber.id}"]:target { scroll-margin-top: calc(min(${scroll}px, 50vh - ${equationNumberHeight}px) + var(--menu-bar-height)); color: var(--warning-border); }`);
	});
}

const formatGloassary = () => {
	const glossaries = document.querySelectorAll('dl');

	glossaries.forEach(glossary => {
		const lists = glossary.querySelectorAll('ul');
		lists.forEach(list => {
			const items = list.querySelectorAll('li');
			const xforms = Array.from(items).map(item => () => {
				const [termP, ...definition] = item.querySelectorAll('p');
				const dt = document.createElement('dt');
				const dtAnchor = document.createElement('a');
				dt.setAttribute('id', `define/${
					termP.innerText.replace(/\s/g, '-').toLowerCase()
				}`);
				dtAnchor.setAttribute('href', `#${dt.getAttribute('id')}`);
				dtAnchor.append(termP.innerText);
				dt.append(dtAnchor);
				termP.remove();
				const div = document.createElement('div');
				div.classList.add('class', 'definition');
				div.setAttribute('role', 'definition');
				div.append(dt);
				const dd = document.createElement('dd');
				dd.append(...definition);
				div.append(dd);
				item.replaceWith(div);
			});
			list.parentElement.append(...list.childNodes);
			list.parentElement.classList.add('glossary');
			list.remove();
			xforms.forEach(xform => xform());
		});
	});

};

figureBlockquoteToCaption = () => {
	const figures = document.querySelectorAll('figure');
	figures.forEach((figure, i) => {
		if (!figure.title) {
			console.warn("No title for figure!", figure);
			figure.title = `untitled-fig ${i + 1}`;
		}
		figure.setAttribute('aria-label', figure.title);
	});
	figures.forEach((figure, i) => {
		if (!figure.id) {
				figure.id = `figure/${figure.title.replace(/\s/g, '-').toLowerCase()}`;
		}
	});
	figures.forEach((figure, i) => {
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
		figureLabel.innerText = `Figure ${i + 1}: ${figure.getAttribute('aria-label')}`;
		figure.prepend(figureLabel);
		caption.append(captionAnchor);
		caption.append(...blockquote.childNodes);
		figure.append(caption);
		blockquote.remove();
	});
};

// This should not be used in a security-sensitive browsing context
const embedPlantuml = async () => {
	const svgImgs = document.querySelectorAll('img[src$=".svg"][src*="mdbook-plantuml"]');
	for (const svgImg of svgImgs) {
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

const fixFootnotes = () => {
	const footnotesSection = document.createElement('section');
	footnotesSection.setAttribute('class', 'footnotes');
	const footnoteDefns = document.querySelectorAll('.footnote-definition');
	if (footnoteDefns.length <= 0) {
		return;
	}
	footnoteDefns.forEach((footnoteDefn, idx) => {
		footnotesSection.append(footnoteDefn);
	});

	const referencesSection = document.querySelector('section.references');
	if (!referencesSection) {
		const main = document.querySelector('main');
		main.appendChild(footnotesSection);
		return;
	}
	referencesSection.parentElement.insertBefore(footnotesSection, referencesSection);
}

const footnoteBacklinks = () => {
	const footnotes = document.querySelectorAll('.footnote-definition');
	if (footnotes.length <= 0) {
		return;
	}
	footnotes.forEach((footnote, idx) => {
		const footnoteId = footnote.getAttribute('id');
		if (!footnoteId) {
			console.warn("No id for footnote: ", footnote);
			return;
		}
		const references = document.querySelectorAll(`.footnote-reference a[href="#${footnoteId}"]`);
		if (references.length <= 0) {
			console.warn("No references for footnote: ", footnote);
			return;
		}
		if (references.length > 1) {
			console.warn("Multiple references for footnote: ", footnote, references);
		}
		references.forEach((reference, _jdx) => {
			reference.setAttribute('id', `ref/footnote/${footnoteId}`);
			reference.setAttribute('data-footnote-id', footnoteId);
			const backReferenceLink = document.createElement('a');
			backReferenceLink.setAttribute('href', `#${reference.id}`);
			backReferenceLink.classList.add('back-reference-source');

			const appendTo = footnote.querySelector(':last-child') ?? footnote;
			appendTo.append(backReferenceLink);
		});
	});
};

const highlight = (id) => {
	document.getElementById(id)?.classList.add('highlight');
};
const unhighlight = (id) => {
	document.getElementById(id)?.classList.remove('highlight');
};

const drawMarkers = () => {
	const markers = ["*", "†", "¶", "‡", "§", "♯"];
	const quals = document.querySelectorAll('[qual]');
	let idx = 0;
	const sheet = document.styleSheets[0];

	const qualMap = new Map();
	quals.forEach(qualElement => {
		if (qualMap.has(qualElement.getAttribute('qual'))) {
			console.warn(`Duplicate qual: ${qualElement.getAttribute('qual')} on element `, qualElement);
			return;
		}
		const qualTag = qualElement.getAttribute('qual');
		if (!qualTag) {
			console.warn("qual tag is empty for element: ", qualElement);
			return;
		}
		qualMap.set(qualTag, qualElement);
		const marker = markers[idx % markers.length];
		const mult = Math.floor(idx / markers.length);
		const markerText = marker.repeat(mult + 1);
		const id = `qual/${markerText}`;
		qualElement.setAttribute('id', id);
		sheet.insertRule(`li:has([id="${id}"])::marker { content: "${markerText} "; font-family: monospace; font-size: 66%; }`);
		idx += 1;
		const pointers = document.querySelectorAll(`[see="${qualTag}"]`);
		let jdx = 1;
		if (pointers && pointers.length && pointers.length === 0) {
			console.warn(`No pointers for qual: ${qualTag}`);
		}
		pointers.forEach(pointer => {
			const markerAnchor = document.createElement('a');
			markerAnchor.classList.add('qualification');
			markerAnchor.classList.add('marker');
			markerAnchor.setAttribute('data-marker', qualTag);
			markerAnchor.setAttribute('id', `see/${markerText}/${jdx}`);
			markerAnchor.setAttribute('href', `#${id}`)
			sheet.insertRule(`a[id="see/${markerText}/${jdx}"]::after { content: "${markerText} "; font-family: monospace; vertical-align: super; font-size: 66%; }`);
			pointer.append(markerAnchor);
			const returnAnchor = document.createElement('a');
			returnAnchor.setAttribute('href', `#see/${markerText}/${jdx}`);
			returnAnchor.classList.add('return-anchor');
			returnAnchor.setAttribute('onmouseover', `highlight("see/${markerText}/${jdx}")`);
			returnAnchor.setAttribute('onmouseout', `unhighlight("see/${markerText}/${jdx}")`);
			qualElement.parentElement.append(returnAnchor);
			jdx += 1;
		});
	});
}

const fillInEquationReferences = () => {
	const equationRefs = document.querySelectorAll('a[href^="#eq/"]');
	equationRefs.forEach(equationRef => {
		if (!equationRef.innerText?.match(/^\(#\)$/)) {
			console.warn(equationRef.innerText, "does not match (#)");
			return;
		}
		console.log("equationRef", equationRef);
		const targetEquation = document.querySelector(`[id="${equationRef.getAttribute('href').slice(1)}"]`);
		if (!targetEquation) {
			console.warn("No target equation for equation reference: ", equationRef);
			return;
		}
		const equationNumber = targetEquation.getAttribute('data-equation-number');
		console.log("equationNumber", equationNumber);
		const equationAnchor = document.createElement('a');
		equationAnchor.setAttribute('href', equationRef.getAttribute('href'));
		equationAnchor.classList.add('ref');
		equationAnchor.innerText = equationRef.innerText.replace(/\(#\)/, `(${equationNumber})`);
		equationRef.replaceWith(equationAnchor);
	});
};

const fillInFigureReferences = () => {
	const figureRefs = document.querySelectorAll('a[href^="#figure/"]');
	figureRefs.forEach(figureRef => {
		if (!figureRef.innerText.match(/\(#\)/)) {
			return;
		}
		const targetFigure = document.querySelector(`[id="${figureRef.getAttribute('href').slice(1)}"]`);
		if (!targetFigure) {
			console.warn("No target figure for figure reference: ", figureRef);
			return;
		}
		const figureNumber = targetFigure.getAttribute('data-figure-number');
		const figureAnchor = document.createElement('a');
		figureAnchor.setAttribute('href', figureRef.getAttribute('href'));
		figureAnchor.classList.add('ref');
		figureAnchor.innerText = figureRef.innerText.replace(/\(#\)$/, figureNumber);
		figureRef.replaceWith(figureAnchor);
	});
};

const embedYoutubeVideos = () => {
	const embedLinks = document.querySelectorAll('a.embed[href^="https://www.youtube.com/watch"]');
	embedLinks.forEach(embedLink => {
		const url = new URL(embedLink.getAttribute('href'));
		const videoId = url.searchParams.get('v');
		const timeCode = url.searchParams.get('t');
		const embed = document.createElement('iframe');
		const src = timeCode ? `https://www.youtube.com/embed/${videoId}?start=${timeCode.replace('s', '')}` : `https://www.youtube.com/embed/${videoId}`;
		embed.setAttribute('src', src);
		embed.setAttribute('frameborder', '0');
		embed.setAttribute('allow', 'accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture');
		embed.setAttribute('allowfullscreen', '');
		embedLink.replaceWith(embed);
	});
};

const smarterSvgBackground = (svg) => {
	const style = window.getComputedStyle(svg);
	if (style.backgroundColor !== 'rgba(0, 0, 0, 0)') {
		console.warn("svg has fill already");
		return;
	}
	svg.style.backgroundColor = 'white';
}

const fixPlantumlSvgBackground = () => {
	const plantumlSvgs = document.querySelectorAll('div.svg-wrapper > svg');
	plantumlSvgs.forEach(smarterSvgBackground);
};

const citeParagraphs = () => {
	const paragraphs = document.querySelectorAll('main > p');
	let paragraphNumber = 0;
	paragraphs.forEach(paragraph => {
		paragraphNumber += 1;
		if (!paragraph.id) {
			paragraph.setAttribute('id', `paragraph/${paragraphNumber}`);
		}
		const citeAnchor = document.createElement('a');
		citeAnchor.classList.add('cite');
		citeAnchor.classList.add('ref-paragraph');
		citeAnchor.setAttribute('data-paragraph-number', paragraphNumber);
		citeAnchor.setAttribute('href', `#${paragraph.id}`);
		paragraph.append(citeAnchor);
	});
};

const format = async () => {
	await embedPlantuml();
	formatBlockcite();
	referencesSection();
	formatBlockQuotes();
	formatEquations()
	formatGloassary();
	citationReferences();
	fixFootnotes();
	drawMarkers();
	fillInEquationReferences();
	fillInFigureReferences();
	figureBlockquoteToCaption();
	footnoteBacklinks();
	embedYoutubeVideos();
	fixPlantumlSvgBackground();
	citeParagraphs();
}

const main = async () => {
	await format();
}

main();
